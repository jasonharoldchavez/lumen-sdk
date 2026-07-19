import hmac
import hashlib
from typing import Dict, Any, List
# Modified to import directly from the local folder context
from sqlite_engine import SQLiteLedgerEngine
from merkle import MerkleTreeEngine

class ForensicAuditVerifier:
    def __init__(self, storage: SQLiteLedgerEngine):
        self.storage = storage

    def verify_journal_row(self, row: List[Any], epoch: int, manifest_hmac: str) -> bool:
        tx_id, ts, node, metric, ver, val_bytes, det_type, det_ver, meta_str, p_hash, c_hash, recorded_hmac, key_id, seq_idx = row
        computed_hmac = self.storage.sign_journal_envelope(
            tx_id, epoch, seq_idx, ts, node, metric, ver, val_bytes,
            det_type, det_ver, meta_str, p_hash, c_hash, manifest_hmac, key_id
        )
        return hmac.compare_digest(computed_hmac, recorded_hmac)

    def verify_state_snapshot(self, row: List[Any]) -> bool:
        node, metric, tx_id, ver, start_ver, state_str, recorded_hmac, key_id = row
        computed_hmac = self.storage.sign_state_envelope(tx_id, node, metric, ver, start_ver, state_str, key_id)
        return hmac.compare_digest(computed_hmac, recorded_hmac)

    async def verify_complete_ledger_chain(self) -> Dict[str, Any]:
        report = {"status": "VERIFIED", "manifests_processed": 0, "errors": []}
        
        expected_prev_hash = b"lumen.compliance.ledger.genesis.v1".hex()
        last_epoch = 0
        last_timestamp = 0

        state_trackers: Dict[str, int] = {}
        stream_hash_trackers: Dict[str, str] = {}

        manifest_cursor = await self.storage._read_conn.execute(
            "SELECT tx_id, logical_epoch, timestamp_nanos, event_count, state_count, manifest_hash, manifest_hmac, key_id, previous_manifest_hash, merkle_root_hash, crypto_algo, hmac_version, hash_version FROM transaction_manifest ORDER BY logical_epoch ASC"
        )
        manifests = await manifest_cursor.fetchall()

        for m in manifests:
            tx_id, epoch, nanos, ev_count, st_count, m_hash, m_hmac, key_id, prev_m_hash, root_hash, algo, hmac_v, hash_v = m
            report["manifests_processed"] += 1

            # 1. Structural Chain Continuity & Monotonicity Validations
            if prev_m_hash != expected_prev_hash:
                report["status"] = "CORRUPTED"
                report["errors"].append(f"Chain fracture at epoch {epoch}: expected parent manifest hash {expected_prev_hash}, found {prev_m_hash}")
            if epoch <= last_epoch:
                report["status"] = "CORRUPTED"
                report["errors"].append(f"Non-monotonic epoch order observed at sequence point {epoch}.")
            if nanos <= last_timestamp:
                report["status"] = "CORRUPTED"
                report["errors"].append(f"Temporal sequence inversion caught at epoch {epoch}.")

            # 2. Recompute Manifest Signature Footprint
            comp_hash, comp_hmac = self.storage.sign_manifest(tx_id, epoch, nanos, ev_count, st_count, prev_m_hash, key_id, root_hash, algo, hmac_v, hash_v)
            if not hmac.compare_digest(comp_hash, m_hash) or not hmac.compare_digest(comp_hmac, m_hmac):
                report["status"] = "CORRUPTED"
                report["errors"].append(f"Manifest authentication error at transaction frame: {tx_id}")

            # 3. Inner Event Journal Chaining & Merkle Validation Pass
            j_cursor = await self.storage._read_conn.execute("SELECT tx_id, timestamp, node, metric, version, value, detector_type, detector_version, metadata, parent_hash, journal_hash, journal_hmac, key_id, sequence_index FROM event_journal WHERE tx_id=? ORDER BY sequence_index ASC", (tx_id,))
            j_rows = await j_cursor.fetchall()
            if len(j_rows) != ev_count:
                report["status"] = "CORRUPTED"
                report["errors"].append(f"Transaction journal dimension mismatch inside block: {tx_id}")

            computed_leaf_hashes = []
            for j_row in j_rows:
                # Assert HMAC envelope seal
                if not self.verify_journal_row(j_row, epoch, m_hmac):
                    report["status"] = "CORRUPTED"
                    report["errors"].append(f"Event node seal invalid inside transaction {tx_id} at sequence idx {j_row[13]}")

                _, _, node, metric, _, _, _, _, _, parent_hash, journal_hash, _, _, _ = j_row
                stream_key = f"{node}:{metric}"
                
                # Validate parent-hash chain continuity per independent telemetry stream
                if stream_key in stream_hash_trackers:
                    expected_parent = stream_hash_trackers[stream_key]
                    if parent_hash != expected_parent:
                        report["status"] = "CORRUPTED"
                        report["errors"].append(f"Stream history modification detected on {stream_key}: parent reference {parent_hash} violates calculated ancestor {expected_parent}")
                else:
                    genesis_marker = "0000000000000000000000000000000000000000000000000000000000000000"
                    if parent_hash != genesis_marker:
                        report["status"] = "CORRUPTED"
                        report["errors"].append(f"Lineage integrity failure: Stream {stream_key} initialized with illegal parent hash context.")

                stream_hash_trackers[stream_key] = journal_hash
                computed_leaf_hashes.append(journal_hash)

            # Dynamically rebuild the internal Merkle Tree from local leaf items to expose internal mutation schemes
            if computed_leaf_hashes:
                recalculated_root = MerkleTreeEngine.compute_root(computed_leaf_hashes)
                if recalculated_root != root_hash:
                    report["status"] = "CORRUPTED"
                    report["errors"].append(f"Merkle verification failure detected at transaction chunk {tx_id}. Root recalculation mismatch.")

            # 4. Detector State Transition Rules Audit
            s_cursor = await self.storage._read_conn.execute("SELECT node, metric, tx_id, version, starting_version, state, state_hmac, key_id FROM detector_state_history WHERE tx_id=?", (tx_id,))
            s_rows = await s_cursor.fetchall()
            if len(s_rows) != st_count:
                report["status"] = "CORRUPTED"
                report["errors"].append(f"State record dimension mismatch inside block: {tx_id}")

            for s_row in s_rows:
                node, metric, _, ver, start_ver, _, _, _ = s_row
                if not self.verify_state_snapshot(s_row):
                    report["status"] = "CORRUPTED"
                    report["errors"].append(f"State snapshot envelope signature failure: {node}:{metric}")
                
                tracker_key = f"{node}:{metric}"
                if tracker_key in state_trackers:
                    expected_start = state_trackers[tracker_key]
                    if start_ver != expected_start:
                        report["status"] = "CORRUPTED"
                        report["errors"].append(f"Broken state progression timeline on {tracker_key}: expected transition start version {expected_start}, found {start_ver}")
                state_trackers[tracker_key] = ver

            expected_prev_hash = m_hash
            last_epoch = epoch
            last_timestamp = nanos

        return report
