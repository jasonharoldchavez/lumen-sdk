import asyncio
import json
import sys
import hashlib
from sqlite_engine import SQLiteLedgerEngine
from merkle import MerkleTreeEngine

class StableKeyProvider:
    def __init__(self):
        self._secret_key = b"lumen_secure_vault_test_key_32b"
    def get_key_material(self, key_id: str) -> bytes:
        return self._secret_key

class LumenLiveNode:
    def __init__(self, listen_host: str, listen_port: int, db_path: str, peer_targets: list):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.db_path = db_path
        self.peer_targets = peer_targets 
        self.kp = StableKeyProvider()
        self.engine = None

    async def start(self):
        self.engine = SQLiteLedgerEngine(self.db_path, self.kp)
        await self.engine.initialize()
        
        self.server = await asyncio.start_server(self.handle_inbound_peer, self.listen_host, self.listen_port)
        print(f"[*] Live Node Online | Interface: {self.listen_host}:{self.listen_port}")
        print(f"[*] Target Routing Mesh: {self.peer_targets}")
        
        async with self.server:
            await self.server.serve_forever()

    async def replicate_to_peers(self, payload):
        for peer_ip, peer_port in self.peer_targets:
            try:
                reader, writer = await asyncio.open_connection(peer_ip, peer_port)
                writer.write(json.dumps(payload).encode())
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                print(f"  [🔄] Real-Network Sync: Replicated to peer at {peer_ip}:{peer_port}")
            except Exception as e:
                print(f"  [⚠️] Live Connection Failed to {peer_ip}:{peer_port}: {str(e)}")

    async def handle_inbound_peer(self, reader, writer):
        data = await reader.read(65536)
        if not data:
            return
        try:
            payload = json.loads(data.decode().strip())
            if payload.get("type") == "BLOCK_BROADCAST":
                tx_id = payload['tx_id']
                is_replicated = payload.get('replicated', False)
                
                print(f"\n[📡] Network Packet Inbound | Tx: {tx_id}")
                
                last_epoch, prev_hash = await self.engine.get_last_manifest_metadata()
                next_epoch = (last_epoch or 0) + 1
                if not prev_hash:
                    prev_hash = b"lumen.compliance.ledger.genesis.v1".hex()
                
                node, metric, key_id = f"node_{self.listen_port}", "live_stream", "kms_key_v1"
                parent_hash = await self.engine.get_last_journal_hash(node, metric)
                val_bytes = b"network_payload_data"
                
                raw_payload = f"{tx_id}:{node}:{metric}:{next_epoch}:{parent_hash}".encode() + val_bytes
                j_hash = hashlib.sha256(raw_payload).hexdigest()
                m_root = MerkleTreeEngine.compute_root([j_hash])
                
                m_hash, m_hmac = self.engine.sign_manifest(tx_id, next_epoch, 1710000000000000000, 1, 1, prev_hash, key_id, m_root, "SHA256", "v1", "v1")
                j_hmac = self.engine.sign_journal_envelope(tx_id, next_epoch, 0, 100.0, node, metric, 1, val_bytes, "CUSUM", "v1", "{}", parent_hash, j_hash, m_hmac, key_id)
                s_hmac = self.engine.sign_state_envelope(tx_id, node, metric, next_epoch, 0, "NORMAL", key_id)
                
                await self.engine.save_compliance_batch_explicit(
                    tx_id, next_epoch, 1710000000000000000, 1, 1, m_hash, m_hmac, key_id, prev_hash, m_root,
                    [(tx_id, 100.0, node, metric, next_epoch, val_bytes, "CUSUM", "v1", "{}", parent_hash, j_hash, j_hmac, key_id, 0)],
                    [],
                    [(node, metric, tx_id, next_epoch, 0, "NORMAL", s_hmac, key_id)]
                )
                print(f"  [✔] Block Certified and Saved locally at Epoch {next_epoch}.")
                
                if not is_replicated:
                    payload['replicated'] = True
                    asyncio.create_task(self.replicate_to_peers(payload))
        except Exception as e:
            print(f"  [❌] Broadcast Verification Error: {str(e)}")
        finally:
            writer.close()
            await writer.wait_closed()

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python3 lumen_live_network.py [PORT] [PEER_IP] [PEER_PORT]")
        sys.exit(1)
        
    port = int(sys.argv[1])
    peer_ip = sys.argv[2]
    peer_port = int(sys.argv[3])
    
    node = LumenLiveNode("0.0.0.0", port, f"live_node_{port}.db", [(peer_ip, peer_port)])
    asyncio.run(node.start())
