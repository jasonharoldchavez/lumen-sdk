import hashlib
from lumen import MerkleTreeEngine

events = [
    "event_one",
    "event_two",
    "event_three"
]

leaf_hashes = [
    hashlib.sha256(event.encode()).hexdigest()
    for event in events
]

root = MerkleTreeEngine.compute_root(leaf_hashes)

print("Lumen SDK Demo")
print("Merkle Root:")
print(root)
