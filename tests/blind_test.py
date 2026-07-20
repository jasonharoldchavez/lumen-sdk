import asyncio
import os
import secrets
import hashlib
import sqlite3
import random
from lumen.ledger import SQLiteLedgerEngine
from verifier import ForensicAuditVerifier
from merkle import MerkleTreeEngine

class EphemeralKeyProvider:
    def __init__(self):
        self._secret_key = secrets.token_bytes(32)
    def get_key_material(self, key_id: str) -> bytes:
        return self._secret_key

async def run_blind_test():
    db_path = "blind_test_ledger.db"
    if os.path.exists(db_path):
        os.remove(db_path)

    key_provider = EphemeralKeyProvider()
    engine = SQLiteLedgerEngine(db_path, key_provider)
    await engine.initialize()
    
    node = "edge_node_alpha"
    metric = "spectral_drift"
    key_id = "kms_key_v1"
    
    print("[*] Generating 100 perfect blocks...")
    for i in range(1, 101):
        tx_id = f"tx_{i:03d}"
        epoch = i
        nanos = 1710000000000000000 + (i * 1000000000)
        
        last_epoch, prev_manifest_hash = await engine.get_last_manifest_metadata()
        parent_hash = await engine.get_last_journal_hash(node, metric)
        
        val_bytes = f"secure_payload_{i}".encode()
        raw_journal_payload = f"{tx_id}:{node}:{metric}:{i}:{parent_hash}".encode() + val_bytes
        journal_hash = hashlib.sha256(raw_journal_payload).hexdigest()
        
        merkle_root = MerkleTreeEngine.compute_root([journal_hash])
        
        m_hash, m_hmac = engine.sign_manifest(tx_id, epoch, nanos, 1, 1, prev_manifest_hash, key_id, merkle_root, "SHA256", "v1", "v1")
        j_hmac = engine.sign_journal_envelope(tx_id, epoch, 0, 1000.0 + i, node, metric, i, val_bytes, "CUSUM", "v1", "{}", parent_hash, journal_hash, m_hmac, key_id)
        s_hmac = engine.sign_state_envelope(tx_id, node, metric, i, i-1, "NORMAL", key_id)
        
        await engine.save_compliance_batch_explicit(tx_id, epoch, nanos, 1, 1, m_hash, m_hmac, key_id, prev_manifest_hash, merkle_root, [(tx_id, 1000.0 + i, node, metric, i, val_bytes, "CUSUM", "v1", "{}", parent_hash, journal_hash, j_hmac, key_id, 0)], [], [(node, metric, tx_id, i, i-1, "NORMAL", s_hmac, key_id)])

    await engine.close()

    # --- THE BLIND ATTACK ---
    # Pick a completely random target block that the verifier code cannot see
    secret_target = random.randint(1, 100)
    target_tx_id = f"tx_{secret_target:03d}"
    print(f"\n[!] [SYSTEM NOTE] A random target was chosen out of sight: {target_tx_id}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # Inject an organic corruption: scramble the payload with random bytes
    cursor.execute("UPDATE event_journal SET value = ? WHERE tx_id = ?", (os.urandom(12), target_tx_id))
    conn.commit()
    conn.close()
    
    # --- THE BLIND FORENSIC SCAN ---
    print("[*] Handing database blindly to the Forensic Auditor...")
    test_engine = SQLiteLedgerEngine(db_path, key_provider)
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
