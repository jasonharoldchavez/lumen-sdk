from lumen import MerkleTreeEngine

import hashlib

print("=== Lumen SDK Basic Usage ===")

events = [
    "sensor_event_001",
    "sensor_event_002",
    "sensor_event_003",
]

# Convert events into SHA256 leaf hashes
leaf_hashes = [
    hashlib.sha256(event.encode()).hexdigest()
    for event in events
]

root = MerkleTreeEngine.compute_root(leaf_hashes)

print("Events:", len(events))
print("Merkle Root:", root)
print("Lumen SDK example completed successfully")
