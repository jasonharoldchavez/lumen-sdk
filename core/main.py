import asyncio
import os
import secrets
import hashlib
# Modified to import directly from the local folder context
from sqlite_engine import SQLiteLedgerEngine
from verifier import ForensicAuditVerifier
from merkle import MerkleTreeEngine

class EphemeralKeyProvider:
    def __init__(self):
        self._secret_key = secrets.token_bytes(32)
    def get_key_material(self, key_id: str) -> bytes:
        return self._secret_key

async def main():
    db_path = "audit_ledger.db"
    if os.path.exists(db_path):
        os.remove(db_path)
        
    print("[*] Initializing Hardened SQLite Ledger Engine...")
    key_provider = EphemeralKeyProvider()
    engine = SQLiteLedgerEngine(db_path, key_provider)
    await engine.initialize()

    tx_id = "tx_001"
    epoch = 1
    nanos = 1710000000000000000
    key_id = "kms_key_v1"
    prev_manifest_hash = b"lumen.compliance.ledger.genesis.v1".hex()

    print("[*] Generating dummy telemetric data stream events...")
    node = "edge_node_alpha"
    metric = "spectral_drift"
    val_bytes = b"\x40\x49\x0f\xdb\x54\x44\x2d\x18"
    
    parent_hash = await engine.get_last_journal_hash(node, metric)
    
    raw_journal_payload = f"{tx_id}:{node}:{metric}:1:{parent_hash}".encode() + val_bytes
    journal_hash = hashlib.sha256(raw_journal_payload).hexdigest()
    
    block_leaves = [journal_hash]
    merkle_root = MerkleTreeEngine.compute_root(block_leaves)

    m_hash, m_hmac = engine.sign_manifest(
        tx_id, epoch, nanos, 1, 1, prev_manifest_hash, key_id, merkle_root, "SHA256", "v1", "v1"
    )

    j_hmac = engine.sign_journal_envelope(
        tx_id, epoch, 0, 1234.56, node, metric, 1, val_bytes, 
        "CUSUM", "v1", "{}", parent_hash, journal_hash, m_hmac, key_id
    )
    journal_rows = [(tx_id, 1234.56, node, metric, 1, val_bytes, "CUSUM", "v1", "{}", parent_hash, journal_hash, j_hmac, key_id, 0)]

    s_hmac = engine.sign_state_envelope(tx_id, node, metric, 1, 0, "NORMAL", key_id)
    state_rows = [(node, metric, tx_id, 1, 0, "NORMAL", s_hmac, key_id)]

    print("[*] Writing atomic cryptographic transaction batch...")
    await engine.save_compliance_batch_explicit(
        tx_id, epoch, nanos, 1, 1, m_hash, m_hmac, key_id, prev_manifest_hash, merkle_root,
        journal_rows, [], state_rows
    )

    print("[*] Starting Forensic Audit Pipeline execution...")
    verifier = ForensicAuditVerifier(engine)
    report = await verifier.verify_complete_ledger_chain()
    
    print("\n================ AUDIT REPORT ================")
    print(f"Status:             {report['status']}")
    print(f"Blocks Audited:     {report['manifests_processed']}")
    print(f"Violations Found:   {len(report['errors'])}")
    print("==============================================\n")

    await engine.close()

if __name__ == "__main__":
    asyncio.run(main())
