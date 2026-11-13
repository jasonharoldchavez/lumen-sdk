# Outcome Attestation Experiment (v0)

## Question

Can a system distinguish an AI agent's claim that it completed a task from independently observed evidence that the required state exists?

## Prototype

The evaluator:
1. Receives an agent claim separately from an observed state snapshot.
2. Checks explicit required key/value conditions against the observed snapshot.
3. Fails closed on missing or contradictory required state.
4. Signs a canonical evidence record with HMAC-SHA256.
5. Binds the record to a task identifier and caller-supplied nonce to detect cross-task substitution and stale replay.

The agent's claim is diagnostic only. It cannot make a failed observation pass.

## Run

From the repository root:

```bash
python -m unittest experiments.outcome_attestation.test_attestor -v
```

No third-party packages are required for this experiment.

## What would count as a result?

The included tests are adversarial unit tests of the prototype's defined behavior: claimed success with failed state, missing evidence, absent snapshots, tampering, replay, and task substitution. A passing suite demonstrates only those tested software properties.

## Critical trust boundary

This is **not** proof that the real world matches a snapshot. It proves that a signed record has not been altered and that the evaluator's rules were applied to the supplied snapshot. The observer may be wrong, compromised, stale, or dishonest. The HMAC key must be protected and the observer must be independent of the agent being evaluated. A production design would need authenticated connectors, freshness guarantees, key rotation, access controls, durable nonce consumption, and independent red-team evaluation.

No commercial, security, or scientific performance claim is made by this prototype.
