import asyncio
import os
import secrets
import hashlib
import sqlite3
from sqlite_engine import SQLiteLedgerEngine
from verifier import ForensicAuditVerifier
from merkle import MerkleTreeEngine

class EphemeralKeyProvider:
    def __init__(self):
        self._secret_key = secrets.token_bytes(32)
    def get_key_material(self, key_id: str) -> bytes:
        return self._secret_key

async def run_validation_suite():
    db_path = "test_audit_ledger.db"
    if os.path.exists(db_path):
        os.remove(db_path)

    key_provider = EphemeralKeyProvider()
    engine = SQLiteLedgerEngine(db_path, key_provider)
    await engine.initialize()
    
    print("[1/3] 🚀 Starting Scale Test: Writing 100 sequential blocks...")
    
    node = "edge_node_alpha"
    metric = "spectral_drift"
    key_id = "kms_key_v1"
    
    for i in range(1, 101):
        tx_id = f"tx_{i:03d}"
        epoch = i
        nanos = 1710000000000000000 + (i * 1000000000) # Monotonic time increments
        
        # 1. Fetch live lineage tail context
        last_epoch, prev_manifest_hash = await engine.get_last_manifest_metadata()
        parent_hash = await engine.get_last_journal_hash(node, metric)
        
        # 2. Build mock transactional payload
        val_bytes = f"payload_data_{i}".encode()
        raw_journal_payload = f"{tx_id}:{node}:{metric}:{i}:{parent_hash}".encode() + val_bytes
        journal_hash = hashlib.sha256(raw_journal_payload).hexdigest()
        
        # 3. Merkle aggregation
        merkle_root = MerkleTreeEngine.compute_root([journal_hash])
        
        # 4. Construct layered signatures
        m_hash, m_hmac = engine.sign_manifest(
            tx_id, epoch, nanos, 1, 1, prev_manifest_hash, key_id, merkle_root, "SHA256", "v1", "v1"
        )
        j_hmac = engine.sign_journal_envelope(
            tx_id, epoch, 0, 1234.56 + i, node, metric, i, val_bytes, 
            "CUSUM", "v1", "{}", parent_hash, journal_hash, m_hmac, key_id
        )
        s_hmac = engine.sign_state_envelope(tx_id, node, metric, i, i-1, "NORMAL", key_id)
        
        # 5. Atomic Batch Write
        journal_rows = [(tx_id, 1234.56 + i, node, metric, i, val_bytes, "CUSUM", "v1", "{}", parent_hash, journal_hash, j_hmac, key_id, 0)]
        state_rows = [(node, metric, tx_id, i, i-1, "NORMAL", s_hmac, key_id)]
        
        await engine.save_compliance_batch_explicit(
            tx_id, epoch, nanos, 1, 1, m_hash, m_hmac, key_id, prev_manifest_hash, merkle_root,
            journal_rows, [], state_rows
        )

    print(f"[2/3] 🛡️  Running forensic audit over clean chain sequence...")
    verifier = ForensicAuditVerifier(engine)
    clean_report = await verifier.verify_complete_ledger_chain()
    print(f"      Result Status:    {clean_report['status']}")
    print(f"      Blocks Audited:   {clean_report['manifests_processed']}")
    print(f"      Violations Found: {len(clean_report['errors'])}")
    
    if clean_report['status'] != "VERIFIED":
        print("❌ Error: Clean ledger failed validation analysis.")
        await engine.close()
        return

    print("[3/3] 🕳️  Simulating adversary attack: Injecting rogue data into transaction 050...")
    await engine.close() # Close async engine safely to allow low-level manual override
    
    # Manually crack open the database file using standard SQLite to bypass your security guards
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # Maliciously flip the metric payload inside transaction 50 without updating signatures
    cursor.execute("UPDATE event_journal SET value = ? WHERE tx_id = ?", (b"TAMPERED_DATA", "tx_050"))
    conn.commit()
    conn.close()
    
    print("      Database modified externally. Re-opening Forensic Verifier...")
    # Restart engine to re-verify the broken chain state
    test_engine = SQLiteLedgerEngine(db_path, key_provider)
    await test_engine.initialize()
    test_verifier = ForensicAuditVerifier(test_engine)
    
    compromised_report = await test_verifier.verify_complete_ledger_chain()
    print("\n================ COMPROMISED AUDIT REPORT ================")
    print(f"Status:             {compromised_report['status']}")
    print(f"Blocks Audited:     {compromised_report['manifests_processed']}")
    print(f"Violations Found:   {len(compromised_report['errors'])}")
    print("Detected Violations:")
    for err in compromised_report['errors']:
        print(f"  [-] {err}")
    print("==========================================================\n")
    
    await test_engine.close()

if __name__ == "__main__":
    asyncio.run(run_validation_suite())
