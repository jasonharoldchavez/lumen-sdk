import asyncio
import os
import hashlib
import time
from lumen.ledger import SQLiteLedgerEngine
from lumen.verifier import ForensicAuditVerifier
from lumen.merkle import MerkleTreeEngine

class StableKeyProvider:
    def __init__(self):
        self._secret_key = b"lumen_secure_vault_test_key_32b"
    def get_key_material(self, key_id: str) -> bytes:
        return self._secret_key

async def run_scale_test():
    db_path = "scale_test.db"
    if os.path.exists(db_path):
        os.remove(db_path)

    kp = StableKeyProvider()
    engine = SQLiteLedgerEngine(db_path, kp)
    await engine.initialize()
    
    node = "edge_node_alpha"
    metric = "spectral_drift"
    key_id = "kms_key_v1"
    
    total_blocks = 5000
    print(f"[*] Phase 1: Generating {total_blocks} chained blocks to simulate real-world scale...")
    
    start_write = time.time()
    
    for i in range(1, total_blocks + 1):
        tx_id = f"tx_scale_{i:05d}"
        epoch = i
        nanos = 1710000000000000000 + (i * 1000)
        
        _, prev_manifest_hash = await engine.get_last_manifest_metadata()
        if i == 1:
            prev_manifest_hash = b"lumen.compliance.ledger.genesis.v1".hex()
            
        parent_hash = await engine.get_last_journal_hash(node, metric)
        val_bytes = f"scale_payload_data_block_{i}".encode()
        raw_journal_payload = f"{tx_id}:{node}:{metric}:{i}:{parent_hash}".encode() + val_bytes
        journal_hash = hashlib.sha256(raw_journal_payload).hexdigest()
        
        merkle_root = MerkleTreeEngine.compute_root([journal_hash])
        
        m_hash, m_hmac = engine.sign_manifest(tx_id, epoch, nanos, 1, 1, prev_manifest_hash, key_id, merkle_root, "SHA256", "v1", "v1")
        j_hmac = engine.sign_journal_envelope(tx_id, epoch, 0, 123.45, node, metric, i, val_bytes, "CUSUM", "v1", "{}", parent_hash, journal_hash, m_hmac, key_id)
        s_hmac = engine.sign_state_envelope(tx_id, node, metric, i, i-1, "NORMAL", key_id)
        
        await engine.save_compliance_batch_explicit(
            tx_id, epoch, nanos, 1, 1, m_hash, m_hmac, key_id, prev_manifest_hash, merkle_root,
            [(tx_id, 123.45, node, metric, i, val_bytes, "CUSUM", "v1", "{}", parent_hash, journal_hash, j_hmac, key_id, 0)],
            [],
            [(node, metric, tx_id, i, i-1, "NORMAL", s_hmac, key_id)]
        )
        
        if i % 1000 == 0:
            print(f"    -> Written {i} blocks...")
            
    end_write = time.time()
    write_duration = end_write - start_write
    tps = total_blocks / write_duration
    
    print(f"    [✔] Successfully wrote {total_blocks} blocks in {write_duration:.2f} seconds ({tps:.2f} tx/sec).")
    await engine.close()
    
    # --- BLIND AUDIT UNDER LOAD ---
    print(f"\n[*] Phase 2: Running a full, blind forensic verification across all {total_blocks} records...")
    
    test_engine = SQLiteLedgerEngine(db_path, kp)
    await test_engine.initialize()
    
    blind_verifier = ForensicAuditVerifier(test_engine)
    
    start_audit = time.time()
    report = await blind_verifier.verify_complete_ledger_chain()
    end_audit = time.time()
    
    audit_duration = end_audit - start_audit
    
    print("\n================ SCALE BENCHMARK RESULTS ================")
    print(f"Total History Audited:  {total_blocks} blocks")
    print(f"Audit Status Verdict:   {report['status']}")
    print(f"Total Execution Time:   {audit_duration:.4f} seconds")
    print(f"Verification Speed:     {total_blocks / audit_duration:.2f} blocks/sec")
    print("=========================================================\n")
    
    await test_engine.close()

if __name__ == "__main__":
    asyncio.run(run_scale_test())
