# Supplemental verifier and test-harness review

Status: static source review of the default branch at commit `cc8887993602e86517ca32ecbff996fde4014a5e`. No code was executed in this review. This is not a security certification or penetration test.

## Confirmed observations

### 1. The forensic verifier does not perform a global orphan-row sweep

`ForensicAuditVerifier.verify_complete_ledger_chain()` iterates transaction manifests, then fetches journal, detector-state, and manifold rows by each manifest's `tx_id`. It checks per-manifest row counts and verifies records it finds. It does not independently query for event-journal, detector-state, or manifold rows whose `tx_id` has no corresponding manifest.

Consequently, an orphan record outside the manifest iteration can be omitted from the audit report. This is especially relevant when a database has been edited by a connection that did not enable SQLite foreign-key enforcement. Add explicit anti-join checks for all three child tables and report any orphan as corruption.

### 2. The test scripts report verdicts but do not consistently assert them

The visible scripts `tests/blind_test.py`, `tests/final_blind_test.py`, `tests/chaos_test.py`, `tests/resiliency_test.py`, and `tests/scale_test.py` print audit results. They do not consistently fail the process when the expected verdict is not obtained. A CI job can therefore finish successfully even when a demonstration did not detect the injected corruption, unless an external test wrapper checks output.

Convert expected outcomes into assertions or non-zero exit codes. For example:
- unmodified ledger: require `VERIFIED`;
- tampered payload/state/manifest: require `CORRUPTED`;
- empty ledger: require the explicitly documented `EMPTY` result;
- orphan rows: require `CORRUPTED`.

### 3. The “blind” and chaos demonstrations are randomized, not independently blinded

The scripts choose random targets and attack types, but the target and attack are printed by the test process. The verifier itself receives the database, so this is useful mutation testing, but it is not a blinded independent security evaluation. Describe it as randomized corruption-injection testing unless a separate operator controls the attack and conceals the target from the evaluator.

### 4. The scale test is a sequential throughput demonstration

`tests/scale_test.py` writes 5,000 one-event manifests sequentially, then audits the ledger. This is useful as a repeatable load demonstration, but it does not test concurrent writers, process crashes during commit, disk-full behavior, power-loss recovery, or multi-node replication. Avoid general scalability or resiliency claims until those separate cases are measured.

## Recommended acceptance tests

1. Create a valid ledger and require a `VERIFIED` result.
2. Add an event row referencing a nonexistent manifest with foreign keys disabled; require `CORRUPTED`.
3. Add orphan state-history and manifold rows; require `CORRUPTED`.
4. Delete the final manifest while leaving child rows; require `CORRUPTED`.
5. Corrupt payload, journal HMAC, manifest HMAC, Merkle root, parent link, state, and matrix bytes independently; require `CORRUPTED` for each.
6. Use a wrong/missing key; require fail-closed behavior and a clear error category.
7. Ensure each test asserts its result and exits non-zero on failure.
8. Run the package from a clean environment and retain machine-readable test output as a CI artifact.

## Scope and limitations

This review inspected selected source files through GitHub's file API. It did not clone the repository, run pytest, execute GitHub Actions, inspect every file or dependency, or test a live database. Findings above are limited to the inspected code paths. No claim is made that these are the only defects.
