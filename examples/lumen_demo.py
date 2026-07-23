from lumen import MerkleTreeEngine
import hashlib
import json
from datetime import datetime

events = [
    {
        "id": 1,
        "action": "user_login",
        "time": str(datetime.now())
    },
    {
        "id": 2,
        "action": "data_export",
        "time": str(datetime.now())
    },
    {
        "id": 3,
        "action": "system_update",
        "time": str(datetime.now())
    }
]

hashes = []

for event in events:
    data = json.dumps(event, sort_keys=True)
    hashes.append(
        hashlib.sha256(data.encode()).hexdigest()
    )

root = MerkleTreeEngine.compute_root(hashes)

print("=== Lumen Audit Proof Demo ===")
print("Events recorded:", len(events))
print("Integrity root:")
print(root)
print("Proof generated successfully")
