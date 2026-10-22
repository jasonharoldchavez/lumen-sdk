# Lumen SDK release-readiness notes

Status: engineering checklist; not a security certification or legal opinion.

## Findings checked on 2026-10-22
- The repository has an Apache-2.0 `LICENSE`, `NOTICE`, and a separate commercial-license information file.
- `pyproject.toml` does not explicitly declare license metadata, despite the README describing an Apache-2.0 community license.
- Multiple GitHub Actions workflows overlap; verify which ones are canonical and remove duplicates only after preserving needed coverage.
- The public README describes an integrity toolkit. A hash, HMAC, or Merkle proof can show consistency with a supplied key/root and recorded inputs; it does not prove that the original data was truthful, that the key was not compromised, or that an attacker with write access could not rewrite the entire history.

## Before publishing
1. Declare package metadata consistent with the actual license and verify the built wheel/sdist metadata.
2. Define the threat model, key creation/storage/rotation, trust anchors, replay protection, concurrency behavior, crash recovery, and backup/restore behavior.
3. Add independent tests for tampered payloads, altered manifests, wrong keys, missing events, reordering, duplicate events, and whole-ledger replacement.
4. Separate integrity checks from authenticity and source-truth claims.
5. Confirm commercial license language does not conflict with Apache-2.0 rights.
6. Test the package in a clean environment and run all canonical CI workflows.

Do not market the SDK as guaranteeing immutability, security, compliance, or truth without specific evidence for each claim.
