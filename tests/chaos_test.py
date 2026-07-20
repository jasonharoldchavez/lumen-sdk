import asyncio
import os
import hashlib
import sqlite3
import random
from lumen.ledger import SQLiteLedgerEngine
from lumen.verifier import ForensicAuditVerifier
from lumen.merkle import MerkleTreeEngine

class StableKeyProvider:
    def __init__(self):
        self._secret_key = b"lumen_secure_vault_test_key_32b"
    def get_key_material(self, key_id: str) -> bytes:
        return self._secret_key

async def run_chaos_test():
    db_path = "chaos_test_ledger.db"
    if os.path.exists(db_path):
        os.remove(db_path)

    kp = StableKeyProvider()
    engine = SQLiteLedgerEngine(db_path, kp)
    await engine.initialize()
    
    node = "edge_node_alpha"
    metric = "spectral_drift"
    key_id = "kms_key_v1"
    
    print("[*] Spreading 100 high-integrity blocks across the ledger...")
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

    # --- INJECTING SIMULTANEOUS MULTI-VECTOR CHAOS ---
    target_delete = random.randint(5, 25)
    target_swap = random.randint(35, 60)
    target_payload = random.randint(70, 80)
    target_state = random.randint(85, 95)
    
    print(f"\n[💥 CHAOS SIMULATION ACTIVATED]")
    print(f"  [-] Deleting record block:        tx_{target_delete:03d}")
    print(f"  [-] Inverting timeline clock at:  tx_{target_swap:03d}")
    print(f"  [-] Corrupting raw data bytes at: tx_{target_payload:03d}")
    print(f"  [-] Forging illegal node state at: tx_{target_state:03d}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # 1. Execute Deletion Attack
    cursor.execute("DELETE FROM transaction_manifest WHERE tx_id = ?", (f"tx_{target_delete:03d}",))
    # 2. Execute Timeline Attack
    cursor.execute("UPDATE transaction_manifest SET timestamp_nanos = 1000 WHERE tx_id = ?", (f"tx_{target_swap:03d}",))
    # 3. Execute Payload Attack
    cursor.execute("UPDATE event_journal SET value = ? WHERE tx_id = ?", (b"INJECTED_MALWARE_STRING_CONFETTI", f"tx_{target_payload:03d}"))
    # 4. Execute State Fork Attack
    cursor.execute("UPDATE detector_state_history SET state = ? WHERE tx_id = ?", ("EXPLOITED", f"tx_{target_state:03d}"))
    
    conn.commit()
    conn.close()
    
    # --- BLIND FORENSIC SCAN ---
    print("\n[*] Handing mutated database blindly to the Forensic Auditor...")
    test_engine = SQLiteLedgerEngine(db_path, kp)
    await test_engine.initialize()
    
    blind_verifier = ForensicAuditVerifier(test_engine)
    report = await blind_verifier.verify_complete_ledger_chain()
    
    print("\n================ FINAL RIGOROUS SCAN RESULTS ================")
    print(f"Audit Verdict:      {report['status']}")
    print(f"Total Violations Identified: {len(report['errors'])}")
    print("Discovered Corruptions:")
    for err in report['errors']:
        print(f"  [ Found ] -> {err}")
    print("=============================================================\n")
    
    await test_engine.close()

if __name__ == "__main__":
    asyncio.run(run_chaos_test())
