"""Outcome attestation prototype: compare claims with independently supplied state.

This prototype does not prove that an observer is honest or that a snapshot came
from the physical world. It makes the trust boundary explicit and detects
claim/state mismatches, missing required state, tampering, and replay when the
caller supplies an expected nonce.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any, Mapping


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


@dataclass(frozen=True)
class Requirement:
    key: str
    expected: Any


@dataclass(frozen=True)
class Attestation:
    verdict: str
    reasons: tuple[str, ...]
    snapshot_hash: str
    evidence: dict[str, Any]
    signature: str


def sign_evidence(evidence: Mapping[str, Any], key: bytes) -> str:
    return hmac.new(key, canonical_json(evidence), hashlib.sha256).hexdigest()


def verify_signature(evidence: Mapping[str, Any], signature: str, key: bytes) -> bool:
    return hmac.compare_digest(sign_evidence(evidence, key), signature)


def attest(
    *,
    task_id: str,
    nonce: str,
    claim: Mapping[str, Any],
    observed_state: Mapping[str, Any] | None,
    requirements: tuple[Requirement, ...],
    observer_id: str,
    signing_key: bytes,
) -> Attestation:
    """Evaluate required state, never treating the agent's claim as evidence."""
    reasons: list[str] = []
    if observed_state is None:
        verdict = "INCONCLUSIVE"
        reasons.append("No independent state snapshot was supplied.")
        snapshot: dict[str, Any] = {}
    else:
        snapshot = dict(observed_state)
        for requirement in requirements:
            if requirement.key not in snapshot:
                reasons.append(f"Missing required state: {requirement.key}")
            elif snapshot[requirement.key] != requirement.expected:
                reasons.append(
                    f"State mismatch for {requirement.key}: "
                    f"expected {requirement.expected!r}, observed {snapshot[requirement.key]!r}"
                )

        # Claims are compared for diagnosis only; they never override observations.
        for key, claimed_value in claim.items():
            if key in snapshot and snapshot[key] != claimed_value:
                reasons.append(f"Claim contradicts observed state for {key}.")

        verdict = "PASS" if not reasons else "FAIL"

    evidence = {
        "schema": "outcome-attestation.v0",
        "task_id": task_id,
        "nonce": nonce,
        "observer_id": observer_id,
        "verdict": verdict,
        "reasons": reasons,
        "snapshot_hash": digest(snapshot) if observed_state is not None else None,
    }
    return Attestation(
        verdict=verdict,
        reasons=tuple(reasons),
        snapshot_hash=evidence["snapshot_hash"] or "",
        evidence=evidence,
        signature=sign_evidence(evidence, signing_key),
    )


def verify_attestation(
    attestation: Attestation,
    *,
    signing_key: bytes,
    expected_task_id: str,
    expected_nonce: str,
) -> tuple[bool, str]:
    """Verify integrity and bind evidence to a caller-provided task/nonce."""
    if not verify_signature(attestation.evidence, attestation.signature, signing_key):
        return False, "Invalid signature or modified evidence."
    if attestation.evidence.get("task_id") != expected_task_id:
        return False, "Task identifier mismatch."
    if attestation.evidence.get("nonce") != expected_nonce:
        return False, "Nonce mismatch (possible replay or wrong task instance)."
    if attestation.evidence.get("verdict") != attestation.verdict:
        return False, "Verdict field mismatch."
    return True, "Evidence integrity and task binding verified; observer truthfulness remains an external trust assumption."
