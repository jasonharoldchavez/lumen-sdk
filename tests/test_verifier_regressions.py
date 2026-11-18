import os
import struct
import tempfile
import sqlite3
import unittest

from lumen.ledger import SQLiteLedgerEngine
from lumen.verifier import ForensicAuditVerifier
from lumen.merkle import MerkleTreeEngine


class TestKeyProvider:
    def get_key_material(self, key_id):
        if key_id != "test-key":
            raise KeyError("unknown test key")
        return b"unit-test-only-key-material"


class VerifierRegressionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite3")
        os.close(fd)
        self.engine = SQLiteLedgerEngine(self.db_path, TestKeyProvider())
        await self.engine.initialize()

    async def asyncTearDown(self):
        await self.engine.close()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(self.db_path + suffix)
            except FileNotFoundError:
                pass

    async def add_valid_manifold(self):
        tx_id, epoch, nanos, key_id = "tx-1", 1, 1710000000000000001, "test-key"
        previous_hash = b"lumen.compliance.ledger.genesis.v1".hex()
        root = MerkleTreeEngine.compute_root([])
        manifest_hash, manifest_hmac = self.engine.sign_manifest(
            tx_id, epoch, nanos, 0, 0, previous_hash, key_id, root, "SHA256", "v1", "v1"
        )
        blob, rows, cols, dtype = struct.pack(">d", 1.25), 1, 1, ">f8"
        timestamp, invariance = 100.0, 0.75
        manifold_hash, manifold_hmac = self.engine.sign_manifold_envelope(
            tx_id, timestamp, blob, rows, cols, dtype, invariance, manifest_hmac, key_id
        )
        await self.engine.save_compliance_batch_explicit(
            tx_id, epoch, nanos, 0, 0, manifest_hash, manifest_hmac, key_id,
            previous_hash, root, [],
            [(tx_id, timestamp, blob, rows, cols, dtype, invariance,
              manifold_hash, manifold_hmac, key_id)], []
        )
        return tx_id

    async def test_empty_ledger_is_not_verified(self):
        report = await ForensicAuditVerifier(self.engine).verify_complete_ledger_chain()
        self.assertEqual(report["status"], "EMPTY")
        self.assertEqual(report["manifests_processed"], 0)

    async def test_valid_manifold_record_verifies(self):
        await self.add_valid_manifold()
        report = await ForensicAuditVerifier(self.engine).verify_complete_ledger_chain()
        self.assertEqual(report["status"], "VERIFIED", report["errors"])
        self.assertEqual(report["manifolds_processed"], 1)

    def inject_orphan_rows(self, tx_id="missing-parent"):
        # A separate SQLite connection defaults foreign_keys to OFF, matching a
        # writer that does not explicitly enable connection-local FK enforcement.
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                """
                INSERT INTO event_journal
                (tx_id, timestamp, node, metric, version, value, detector_type,
                 detector_version, metadata, parent_hash, journal_hash,
                 journal_hmac, key_id, sequence_index)
                VALUES (?, 1.0, 'orphan-node', 'orphan-metric', 1, X'01',
                        'test', 'v1', '{}', '0', '1', 'bad', 'test-key', 0)
                """,
                (tx_id,),
            )
            conn.execute(
                """
                INSERT INTO detector_state_history
                (node, metric, tx_id, version, starting_version, state, state_hmac, key_id)
                VALUES ('orphan-node', 'orphan-metric', ?, 1, 0, 'NORMAL', 'bad', 'test-key')
                """,
                (tx_id,),
            )
            conn.execute(
                """
                INSERT INTO causal_manifold_journal
                (tx_id, timestamp, causal_matrix_blob, matrix_rows, matrix_cols,
                 matrix_dtype, structural_invariance_index, manifold_hash, manifold_hmac, key_id)
                VALUES (?, 1.0, X'0000000000000000', 1, 1, '>f8', 0.5, 'bad', 'bad', 'test-key')
                """,
                (tx_id,),
            )
            conn.commit()
        finally:
            conn.close()

    async def test_orphan_rows_are_detected_even_when_ledger_has_no_manifests(self):
        self.inject_orphan_rows()
        report = await ForensicAuditVerifier(self.engine).verify_complete_ledger_chain()
        self.assertEqual(report["status"], "CORRUPTED", report["errors"])
        self.assertEqual(
            report["orphan_records"],
            {
                "event_journal": 1,
                "detector_state_history": 1,
                "causal_manifold_journal": 1,
            },
        )
        self.assertEqual(report["manifests_processed"], 0)

    async def test_orphan_rows_are_detected_alongside_valid_manifest(self):
        await self.add_valid_manifold()
        self.inject_orphan_rows("missing-parent-with-valid-ledger")
        report = await ForensicAuditVerifier(self.engine).verify_complete_ledger_chain()
        self.assertEqual(report["status"], "CORRUPTED", report["errors"])
        self.assertEqual(report["manifests_processed"], 1)
        self.assertEqual(report["orphan_records"]["event_journal"], 1)
        self.assertEqual(report["orphan_records"]["detector_state_history"], 1)
        self.assertEqual(report["orphan_records"]["causal_manifold_journal"], 1)

    async def test_modified_manifold_matrix_is_detected(self):
        tx_id = await self.add_valid_manifold()
        await self.engine._write_conn.execute(
            "UPDATE causal_manifold_journal SET causal_matrix_blob=? WHERE tx_id=?",
            (b"\x00" * 8, tx_id)
        )
        await self.engine._write_conn.commit()
        report = await ForensicAuditVerifier(self.engine).verify_complete_ledger_chain()
        self.assertEqual(report["status"], "CORRUPTED")
        self.assertTrue(any("Manifold authentication failure" in e for e in report["errors"]))

    async def test_invalid_manifold_key_fails_closed(self):
        tx_id = await self.add_valid_manifold()
        await self.engine._write_conn.execute(
            "UPDATE causal_manifold_journal SET key_id=? WHERE tx_id=?",
            ("unknown-key", tx_id)
        )
        await self.engine._write_conn.commit()
        report = await ForensicAuditVerifier(self.engine).verify_complete_ledger_chain()
        self.assertEqual(report["status"], "CORRUPTED")
        self.assertTrue(any("Manifold transaction/key binding mismatch" in e for e in report["errors"]))


if __name__ == "__main__":
    unittest.main()
