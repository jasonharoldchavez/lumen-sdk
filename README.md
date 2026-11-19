# Lumen SDK

## Current status

Lumen SDK is an **early-stage Python toolkit for hashing and checking the integrity of locally stored event-ledger records**. The current installable package exposes three components:

- `MerkleTreeEngine`: computes a Merkle root from caller-supplied hexadecimal leaf hashes.
- `SQLiteLedgerEngine`: initializes and writes the SQLite ledger schema, provides cryptographic signing helpers, and saves explicitly assembled transaction batches.
- `ForensicAuditVerifier`: checks manifests and associated journal, state-history, and causal-manifold records, including orphan-record detection.

The package is under active engineering review. Do not treat it as a complete production ledger, a distributed consensus system, a compliance product, or a security certification.

## Installation

```bash
python -m pip install lumen-sdk
```

The current project metadata declares version `0.5.0` and Python `>=3.10`.

## Quick start: Merkle root

This example demonstrates the Merkle helper only. It does not create a ledger, authenticate data, or prove that source events are truthful.

```python
import hashlib
from lumen import MerkleTreeEngine

events = [b"event one", b"event two", b"event three"]
leaf_hashes = [hashlib.sha256(event).hexdigest() for event in events]
root = MerkleTreeEngine.compute_root(leaf_hashes)

print(root)
```

## SQLite ledger API

The low-level ledger API requires the application to supply a key-provider object with a `get_key_material(key_id)` method. The application is responsible for secure key generation, storage, access control, rotation, and backup.

The current write interface is deliberately explicit: callers must assemble and authenticate manifest, journal, state, and optional manifold records before calling `save_compliance_batch_explicit(...)`. This release does **not** provide a high-level event-ingestion API that automatically performs that entire workflow.

A minimal initialization shape is:

```python
import asyncio
from lumen import SQLiteLedgerEngine

class KeyProvider:
    def get_key_material(self, key_id: str) -> bytes:
        # Replace with a real secret-management integration.
        # Never hard-code production keys in application source.
        raise NotImplementedError

async def main():
    ledger = SQLiteLedgerEngine("ledger.sqlite3", KeyProvider())
    try:
        await ledger.initialize()
        # Assemble and authenticate records using the documented low-level
        # API before writing a transaction batch.
    finally:
        await ledger.close()

asyncio.run(main())
```

The placeholder key provider intentionally cannot write authenticated records until the application implements secure key retrieval.

## What is included in the Python distribution

The configured package discovery includes the `lumen` Python package. The repository also contains a separate `core/` directory with prototype scripts and network experiments; those files are **not included as importable modules in the published `lumen-sdk` distribution** under the current package configuration.

Do not assume that installing `lumen-sdk` installs or enables the separate network experiments.

## Integrity model and limitations

The implementation uses SHA-256 hashing and HMAC authentication with caller-provided key material. Merkle roots summarize the supplied leaf hashes. The verifier checks recorded relationships and authentication values against the records and keys available to it.

These mechanisms can help detect certain changes to records when the verifier has trustworthy keys and a trustworthy reference point. They do not, by themselves:

- prove that incoming measurements or events were true;
- prove who originally created an event;
- provide trusted timestamps;
- prevent a privileged attacker from replacing the database and all reference values;
- provide external anchoring, consensus, or distributed fault tolerance;
- guarantee immutability or prevent all attacks;
- provide regulatory compliance or security certification.

The current implementation and threat model remain under review. Concurrency, crash recovery, backup/restore, key lifecycle, whole-ledger replacement, and deployment security must be independently evaluated before production use.

## Tests

The repository contains assertion-based verifier regression tests and additional historical validation/demo scripts. Passing a demo script is not equivalent to proving every advertised property. See the GitHub Actions workflows and test files for the exact checks currently run.

## Licensing

The repository includes an Apache License 2.0 `LICENSE` and a separate `COMMERCIAL_LICENSE.md`. The exact legal effect and compatibility of the proposed dual-licensing language have not been independently reviewed. Review the license texts and obtain legal advice before relying on any commercial licensing interpretation.

## Development status

This project is being audited and improved. The published `0.5.0` package should be treated as an early-stage release, not as a claim that all repository experiments or advertised capabilities are production-ready.

## Project

Repository: https://github.com/jasonharoldchavez/lumen-sdk
