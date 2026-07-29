from lumen import MerkleTreeEngine

events = [
    "event_one",
    "event_two",
    "event_three"
]

root = MerkleTreeEngine.compute_root(events)

print("Lumen SDK Demo")
print("Merkle Root:")
print(root)
