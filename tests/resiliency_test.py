import asyncio
import os
import hashlib
import sqlite3
from lumen.ledger import SQLiteLedgerEngine
from verifier import ForensicAuditVerifier
from merkle import MerkleTreeEngine

class StableKeyProvider:
    def __init__(self):
        self._secret_key = b"lumen_secure_vault_test_key_32b"
    def get_key_material(self, key_id: str) -> bytes:
        return self._secret_key

async def write_sequential_pressure(engine, total_writes):
    node = "edge_node_alpha"
    metric = "spectral_drift"
    key_id = "kms_key_v1"
    
    # We execute sequentially here to stress the ledger's capability to safely chain blocks one after the other
    for i in range(1, total_writes + 1):
        tx_id = f"tx_press_{i:03d}"
        epoch = i
        nanos = 1710000000000000000 + (i * 1000)
        
        _, prev_manifest_hash = await engine.get_last_manifest_metadata()
        if i == 1:
            prev_manifest_hash = b"lumen.compliance.ledger.genesis.v1".hex()
            
        parent_hash = await engine.get_last_journal_hash(node, metric)
        
        val_bytes = f"pressure_data_{i}".encode()
        raw_journal_payload = f"{tx_id}:{node}:{metric}:{i}:{parent_hash}".encode() + val_bytes
        journal_hash = hashlib.sha256(raw_journal_payload).hexdigest()
        
        merkle_root = MerkleTreeEngine.compute_root([journal_hash])
        
        m_hash, m_hmac = engine.sign_manifest(tx_id, epoch, nanos, 1, 1, prev_manifest_hash, key_id, merkle_root, "SHA256", "v1", "v1")
        j_hmac = engine.sign_journal_envelope(tx_id, epoch, 0, 99.9, node, metric, i, val_bytes, "CUSUM", "v1", "{}", parent_hash, journal_hash, m_hmac, key_id)
        s_hmac = engine.sign_state_envelope(tx_id, node, metric, i, i-1, "NORMAL", key_id)
        
        await engine.save_compliance_batch_explicit(
            tx_id, epoch, nanos, 1, 1, m_hash, m_hmac, key_id, prev_manifest_hash, merkle_root,
            [(tx_id, 99.9, node, metric, i, val_bytes, "CUSUM", "v1", "{}", parent_hash, journal_hash, j_hmac, key_id, 0)],
            [],
            [(node, metric, tx_id, i, i-1, "NORMAL", s_hmac, key_id)]
        )

async def run_resiliency_test():
    db_path = "resiliency_test.db"
    if os.path.exists(db_path):
        os.remove(db_path)

    kp = StableKeyProvider()
    engine = SQLiteLedgerEngine(db_path, kp)
    await engine.initialize()
    
    print("[*] Phase 1: Applying sequential write load (20 blocks)...")
    try:
        await write_sequential_pressure(engine, 20)
        print("    -> Load phase completed safely.")
    except Exception as e:
        print(f"    [❌] Load phase failed: {str(e)}")
        
    await engine.close()
    
    print("\n[*] Phase 2: Simulating partial-write crash state (injecting orphan manifest)...")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Injecting an incomplete manifest entry with your exact schema matching layout
    cursor.execute("""
        INSERT INTO transaction_manifest (
            tx_id, logical_epoch, timestamp_nanos, event_count, state_count, 
            manifest_hash, manifest_hmac, key_id, previous_manifest_hash, 
            merkle_root_hash, crypto_algo, hmac_version, hash_version
        )
        VALUES (
            'tx_crash_999', 999, 1710000000000000000, 1, 1, 
            'fake_hash', 'fake_hmac', 'kms_key_v1', 'garbage_parent', 
            'garbage_root', 'SHA256', 'v1', 'v1'
        )
    """)
    conn.commit()
    conn.close()
    print("    -> Incomplete state written. Handing database blindly to Forensic Verifier...")
    
    test_engine = SQLiteLedgerEngine(db_path, kp)
    await test_engine.initialize()
    
    blind_verifier = ForensicAuditVerifier(test_engine)
    report = await blind_verifier.verify_complete_ledger_chain()
    
    print("\n================ RESILIENCY SCAN RESULTS ================")
    print(f"Audit Verdict:      {report['status']}")
    print(f"Total Violations Identified: {len(report['errors'])}")
    print("Discovered Corruptions:")
    for err in report['errors']:
        print(f"  [ Found ] -> {err}")
    print("=========================================================\n")
    
    await test_engine.close()

if __name__ == "__main__":
    asyncio.run(run_resiliency_test())
