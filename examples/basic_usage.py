from lumen import MerkleTreeEngine

events = [
    "event_001_hash",
    "event_002_hash",
    "event_003_hash"
]

root = MerkleTreeEngine.compute_root(events)

print("Lumen Merkle Root:")
print(root)
