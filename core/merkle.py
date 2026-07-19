import hashlib
from typing import List

class MerkleTreeEngine:
    @staticmethod
    def compute_root(leaf_hashes: List[str]) -> str:
        """
        Takes a list of hex-encoded SHA-256 journal hashes,
        pairs and hashes them hierarchically, and returns the single Merkle Root hex string.
        """
        if not leaf_hashes:
            return "0000000000000000000000000000000000000000000000000000000000000000"
            
        current_level = [bytes.fromhex(h) for h in leaf_hashes]
        
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                if i + 1 < len(current_level):
                    # Pair adjacent nodes chunks
                    combined = current_level[i] + current_level[i + 1]
                else:
                    # Duplicate odd node to maintain balanced canonical symmetry
                    combined = current_level[i] + current_level[i]
                next_level.append(hashlib.sha256(combined).digest())
            current_level = next_level
            
        return current_level[0].hex()
