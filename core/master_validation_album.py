import asyncio
import os
import hashlib
import sqlite3
import time
import random
from sqlite_engine import SQLiteLedgerEngine
from verifier import ForensicAuditVerifier
from merkle import MerkleTreeEngine

class StableKeyProvider:
    def __init__(self):
        self._secret_key = b"lumen_secure_vault_test_key_32b"
    def get_key_material(self, key_id: str) -> bytes:
        return self._secret_key

async def populate_chain(engine, total, node, metric, key_id):
    for i in range(1, total + 1):
        tx_id = f"tx_{i:04d}"
        epoch = i
        nanos = 1710000000000000000 + (i * 1000000000)
        
        _, prev_manifest_hash = await engine.get_last_manifest_metadata()
        if i == 1:
            prev_manifest_hash = b"lumen.compliance.ledger.genesis.v1".hex()
            
        parent_hash = await engine.get_last_journal_hash(node, metric)
        val_bytes = f"payload_data_stream_{i}".encode()
        raw_journal_payload = f"{tx_id}:{node}:{metric}:{i}:{parent_hash}".encode() + val_bytes
        journal_hash = hashlib.sha256(raw_journal_payload).hexdigest()
        
        merkle_root = MerkleTreeEngine.compute_root([journal_hash])
        
        m_hash, m_hmac = engine.sign_manifest(tx_id, epoch, nanos, 1, 1, prev_manifest_hash, key_id, merkle_root, "SHA256", "v1", "v1")
        j_hmac = engine.sign_journal_envelope(tx_id, epoch, 0, 50.0, node, metric, i, val_bytes, "CUSUM", "v1", "{}", parent_hash, journal_hash, m_hmac, key_id)
        s_hmac = engine.sign_state_envelope(tx_id, node, metric, i, i-1, "NORMAL", key_id)
        
        await engine.save_compliance_batch_explicit(
            tx_id, epoch, nanos, 1, 1, m_hash, m_hmac, key_id, prev_manifest_hash, merkle_root,
            [(tx_id, 50.0, node, metric, i, val_bytes, "CUSUM", "v1", "{}", parent_hash, journal_hash, j_hmac, key_id, 0)],
            [],
            [(node, metric, tx_id, i, i-1, "NORMAL", s_hmac, key_id)]
        )

async def main():
    db_path = "master_validation.db"
    kp = StableKeyProvider()
    node, metric, key_id = "edge_node_alpha", "spectral_drift", "kms_key_v1"

    print("=====================================================")
    print("      LUMEN CRYPTO-LEDGER VALIDATION ALBUM           ")
    print("=====================================================\n")

    # --- PHASE 1: MICRO-DRIFT TIME ATTACK ---
    if os.path.exists(db_path): os.remove(db_path)
    engine = SQLiteLedgerEngine(db_path, kp)
    await engine.initialize()
    print("[*] ALBUM TRACK 1: Executing Micro-Drift Time Attack...")
    await populate_chain(engine, 100, node, metric, key_id)
    await engine.close()
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp_nanos FROM transaction_manifest WHERE tx_id = 'tx_0050'")
    original_time = cursor.fetchone()[0]
    cursor.execute("UPDATE transaction_manifest SET timestamp_nanos = ? WHERE tx_id = 'tx_0050'", (original_time - 5000000000,))
    conn.commit()
    conn.close()
    
    engine = SQLiteLedgerEngine(db_path, kp)
    await engine.initialize()
    verifier = ForensicAuditVerifier(engine)
    report = await verifier.verify_complete_ledger_chain()
    print(f"  [-] Audit Result: {report['status']} | Caught Errors: {len(report['errors'])}")
    for err in report['errors']: print(f"    [🚨] {err}")
    await engine.close()

    # --- PHASE 2: SYNCHRONIZED CHAOS COLLAPSE ---
    if os.path.exists(db_path): os.remove(db_path)
    engine = SQLiteLedgerEngine(db_path, kp)
    await engine.initialize()
    print("\n[*] ALBUM TRACK 2: Executing Synchronized Chaos Collapse...")
    await populate_chain(engine, 100, node, metric, key_id)
    await engine.close()
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM transaction_manifest WHERE tx_id = 'tx_0025'")
    # Injecting raw binary BLOB hex instead of a string literal
    cursor.execute("UPDATE event_journal SET value = X'414c54455245445f44415441' WHERE tx_id = 'tx_0075'") 
    cursor.execute("UPDATE detector_state_history SET state = 'FORGED_STATE' WHERE tx_id = 'tx_0090'") 
    conn.commit()
    conn.close()
    
    engine = SQLiteLedgerEngine(db_path, kp)
    await engine.initialize()
    verifier = ForensicAuditVerifier(engine)
    report = await verifier.verify_complete_ledger_chain()
    print(f"  [-] Audit Result: {report['status']} | Caught Errors: {len(report['errors'])}")
    for err in report['errors']: print(f"    [🚨] {err}")
    await engine.close()

    # --- PHASE 3: MASSIVE LINEAR SCALE VERIFICATION ---
    if os.path.exists(db_path): os.remove(db_path)
    engine = SQLiteLedgerEngine(db_path, kp)
    await engine.initialize()
    scale_count = 2000
    print(f"\n[*] ALBUM TRACK 3: Measuring Performance Floor at {scale_count} Clean Blocks...")
    
    t0 = time.time()
    await populate_chain(engine, scale_count, node, metric, key_id)
    t1 = time.time()
    await engine.close()
    
    engine = SQLiteLedgerEngine(db_path, kp)
    await engine.initialize()
    verifier = ForensicAuditVerifier(engine)
    
    t2 = time.time()
    report = await verifier.verify_complete_ledger_chain()
    t3 = time.time()
    
    print(f"  [-] Write Performance: {(scale_count / (t1 - t0)):.2f} tx/sec")
    print(f"  [-] Audit Performance: {(scale_count / (t3 - t2)):.2f} blocks/sec")
    print(f"  [-] Verification Status: {report['status']}")
    await engine.close()
    
    print("\n=====================================================")
    print("         ALL ALBUM VALIDATIONS COMPLETE              ")
    print("=====================================================")

if __name__ == "__main__":
    asyncio.run(main())
