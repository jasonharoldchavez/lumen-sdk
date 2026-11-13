import unittest

from experiments.outcome_attestation.attestor import (
    Requirement, attest, verify_attestation,
)


class OutcomeAttestationTests(unittest.TestCase):
    def setUp(self):
        self.key = b"test-only-secret-key"
        self.requirements = (
            Requirement("payment_status", "settled"),
            Requirement("receipt_id", "rcpt-123"),
        )

    def make(self, state, claim=None, nonce="fresh-001"):
        return attest(
            task_id="task-42",
            nonce=nonce,
            claim=claim or {"payment_status": "settled"},
            observed_state=state,
            requirements=self.requirements,
            observer_id="test-observer",
            signing_key=self.key,
        )

    def test_matching_observed_state_passes(self):
        result = self.make({"payment_status": "settled", "receipt_id": "rcpt-123"})
        self.assertEqual(result.verdict, "PASS")

    def test_claimed_success_does_not_override_failed_state(self):
        result = self.make(
            {"payment_status": "pending", "receipt_id": "rcpt-123"},
            {"payment_status": "settled"},
        )
        self.assertEqual(result.verdict, "FAIL")
        self.assertTrue(any("mismatch" in reason.lower() for reason in result.reasons))

    def test_missing_state_fails_closed(self):
        result = self.make({"payment_status": "settled"})
        self.assertEqual(result.verdict, "FAIL")
        self.assertTrue(any("missing" in reason.lower() for reason in result.reasons))

    def test_no_snapshot_is_inconclusive_not_success(self):
        result = attest(
            task_id="task-42", nonce="fresh-001", claim={"payment_status": "settled"},
            observed_state=None, requirements=self.requirements,
            observer_id="test-observer", signing_key=self.key,
        )
        self.assertEqual(result.verdict, "INCONCLUSIVE")

    def test_tampering_is_detected(self):
        result = self.make({"payment_status": "settled", "receipt_id": "rcpt-123"})
        result.evidence["verdict"] = "FAIL"
        ok, reason = verify_attestation(
            result, signing_key=self.key,
            expected_task_id="task-42", expected_nonce="fresh-001",
        )
        self.assertFalse(ok)
        self.assertIn("signature", reason.lower())

    def test_replay_nonce_is_rejected(self):
        result = self.make({"payment_status": "settled", "receipt_id": "rcpt-123"})
        ok, reason = verify_attestation(
            result, signing_key=self.key,
            expected_task_id="task-42", expected_nonce="fresh-002",
        )
        self.assertFalse(ok)
        self.assertIn("nonce", reason.lower())

    def test_wrong_task_is_rejected(self):
        result = self.make({"payment_status": "settled", "receipt_id": "rcpt-123"})
        ok, reason = verify_attestation(
            result, signing_key=self.key,
            expected_task_id="other-task", expected_nonce="fresh-001",
        )
        self.assertFalse(ok)
        self.assertIn("task", reason.lower())


if __name__ == "__main__":
    unittest.main()
