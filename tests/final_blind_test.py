import asyncio
import os
import hashlib
import sqlite3
import random
from lumen.ledger import SQLiteLedgerEngine
from verifier import ForensicAuditVerifier
from merkle import MerkleTreeEngine

class StableKeyProvider:
    def __init__(self):
        self._secret_key = b"lumen_secure_vault_test_key_32b"
    def get_key_material(self, key_id: str) -> bytes:
        return self._secret_key

async def run_blind_test():
    db_path = "final_blind_test.db"
    if os.path.exists(db_path):
        os.remove(db_path)

    kp = StableKeyProvider()
    engine = SQLiteLedgerEngine(db_path, kp)
    await engine.initialize()
    
    node = "edge_node_alpha"
    metric = "spectral_drift"
    key_id = "kms_key_v1"
    
    print("[*] Generating 100 perfectly chained blocks...")
    for i in range(1, 101):
        tx_id = f"tx_{i:03d}"
        epoch = i
        nanos = 1710000000000000000 + (i * 1000000000)
        
        _, prev_manifest_hash = await engine.get_last_manifest_metadata()
        if i == 1:
            prev_manifest_hash = b"lumen.compliance.ledger.genesis.v1".hex()
            
        parent_hash = await engine.get_last_journal_hash(node, metric)
        
        val_bytes = f"secure_data_payload_{i}".encode()
        raw_journal_payload = f"{tx_id}:{node}:{metric}:{i}:{parent_hash}".encode() + val_bytes
        journal_hash = hashlib.sha256(raw_journal_payload).hexdigest()
        
        merkle_root = MerkleTreeEngine.compute_root([journal_hash])
        
        m_hash, m_hmac = engine.sign_manifest(tx_id, epoch, nanos, 1, 1, prev_manifest_hash, key_id, merkle_root, "SHA256", "v1", "v1")
        j_hmac = engine.sign_journal_envelope(tx_id, epoch, 0, 100.0 * i, node, metric, i, val_bytes, "CUSUM", "v1", "{}", parent_hash, journal_hash, m_hmac, key_id)
        s_hmac = engine.sign_state_envelope(tx_id, node, metric, i, i-1, "NORMAL", key_id)
        
        await engine.save_compliance_batch_explicit(
            tx_id, epoch, nanos, 1, 1, m_hash, m_hmac, key_id, prev_manifest_hash, merkle_root,
            [(tx_id, 100.0 * i, node, metric, i, val_bytes, "CUSUM", "v1", "{}", parent_hash, journal_hash, j_hmac, key_id, 0)],
            [],
            [(node, metric, tx_id, i, i-1, "NORMAL", s_hmac, key_id)]
        )
    
    await engine.close()

    # --- CHOOSE A RANDOM ATTACK TYPE AND TARGET ---
    attack_type = random.choice(["deletion", "timestamp_swap", "state_corruption"])
    random_target = random.randint(5, 95) # Pick a random block in the middle
    target_tx = f"tx_{random_target:03d}"
    
    print(f"\n[!] Background System Action: Executing a random '{attack_type}' attack on target: {target_tx}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    if attack_type == "deletion":
        cursor.execute("DELETE FROM transaction_manifest WHERE tx_id = ?", (target_tx,))
    elif attack_type == "timestamp_swap":
        # Force a broken timestamp order
        cursor.execute("UPDATE transaction_manifest SET timestamp_nanos = 1000000 WHERE tx_id = ?", (target_tx,))
    elif attack_type == "state_corruption":
        cursor.execute("UPDATE detector_state_history SET state = 'BAD_DATA' WHERE tx_id = ?", (target_tx,))
        
    conn.commit()
    conn.close()
    
    # --- BLIND AUDIT RUN ---
    print("[*] Handing database completely blindly to the Forensic Auditor...")
    test_engine = SQLiteLedgerEngine(db_path, kp)
    await test_engine.initialize()
    
    blind_verifier = ForensicAuditVerifier(test_engine)
    report = await blind_verifier.verify_complete_ledger_chain()
    
    print("\n================ BLIND SCAN RESULTS ================")
    print(f"Audit Verdict:      {report['status']}")
    print(f"Total Violations:   {len(report['errors'])}")
    print("Discovered Corruptions:")
    for err in report['errors']:
        print(f"  [ Found ] -> {err}")
    print("====================================================\n")
    
    await test_engine.close()

if __name__ == "__main__":
    asyncio.run(run_blind_test())
