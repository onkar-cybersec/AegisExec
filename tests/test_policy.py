"""
Unit tests for AegisExec Policy Engine.
Tests decision generation, allow/deny rules, timeout bounds, and fail-closed approval verification.
"""

import os
import shutil
import tempfile
import unittest

from aegisexec.policy import PolicyEngine


class TestPolicy(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="aegis_policy_test_")
        self.sample_file = os.path.join(self.temp_dir, "data.txt")
        with open(self.sample_file, "w", encoding="utf-8") as f:
            f.write("Sample test data")

        self.policy_dict = {
            "schema_version": "1.0",
            "policy_id": "pol-unit-test",
            "name": "Unit Test Policy",
            "workspace_root": self.temp_dir,
            "allowed_operations": ["read_text", "list_dir", "run_python"],
            "path_rules": {
                "allowed_subpaths": [],
                "denied_patterns": [".env"],
                "max_file_read_bytes": 1024,
            },
            "execution_rules": {
                "max_timeout_seconds": 10,
                "allow_network": False,
            },
            "require_approval_for": ["run_python"],
        }
        self.engine = PolicyEngine(self.policy_dict)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_benign_read_allowed(self):
        req = {
            "schema_version": "1.0",
            "request_id": "req-read-ok",
            "operation": "read_text",
            "parameters": {"path": "data.txt"},
        }
        decision = self.engine.evaluate(req)
        self.assertEqual(decision.status, "ALLOWED")
        self.assertEqual(decision.operation, "read_text")
        self.assertTrue(decision.decision_id.startswith("dec-"))
        self.assertIn("filesystem.boundary_confinement", decision.matched_rules)

    def test_read_beyond_size_quota_denied(self):
        req = {
            "schema_version": "1.0",
            "request_id": "req-read-big",
            "operation": "read_text",
            "parameters": {"path": "data.txt", "max_bytes": 50000},
        }
        decision = self.engine.evaluate(req)
        self.assertEqual(decision.status, "DENIED")
        self.assertIn("exceeds policy max", decision.reason)
        self.assertIn("filesystem.size_quota", decision.matched_rules)

    def test_operation_not_in_allowlist_denied(self):
        strict_policy = dict(self.policy_dict)
        strict_policy["allowed_operations"] = ["read_text"]
        strict_policy["require_approval_for"] = []
        engine = PolicyEngine(strict_policy)

        req = {
            "schema_version": "1.0",
            "request_id": "req-list-denied",
            "operation": "list_dir",
            "parameters": {"path": "."},
        }
        decision = engine.evaluate(req)
        self.assertEqual(decision.status, "DENIED")
        self.assertIn("not in policy allowed_operations", decision.reason)

    def test_approval_required_rejected_fail_closed(self):
        # Even if an unverified text token is supplied, approval-required ops fail closed
        req = {
            "schema_version": "1.0",
            "request_id": "req-py-token",
            "operation": "run_python",
            "parameters": {"code": "print(1)"},
            "approval": {
                "approved_by": "sec-admin",
                "token": "unverified-text-token-abc",
            },
        }
        decision = self.engine.evaluate(req)
        self.assertEqual(decision.status, "DENIED")
        self.assertIn("rejected fail-closed", decision.reason)
        self.assertIn("access_control.approval_required_fail_closed", decision.matched_rules)

    def test_forged_approval_never_bypasses_path_traversal(self):
        req = {
            "schema_version": "1.0",
            "request_id": "req-forged-approval",
            "operation": "read_text",
            "parameters": {"path": "../../etc/shadow"},
            "approval": {
                "approved_by": "attacker",
                "token": "fake-token",
            },
        }
        decision = self.engine.evaluate(req)
        self.assertEqual(decision.status, "DENIED")
        self.assertIn("Path boundary check failed", decision.reason)

    def test_excessive_timeout_denied_by_policy(self):
        req = {
            "schema_version": "1.0",
            "request_id": "req-py-timeout",
            "operation": "run_python",
            "parameters": {"code": "print(1)", "timeout_seconds": 25},
        }
        # Disable require_approval_for to isolate timeout evaluation
        policy = dict(self.policy_dict)
        policy["require_approval_for"] = []
        engine = PolicyEngine(policy)

        decision = engine.evaluate(req)
        self.assertEqual(decision.status, "DENIED")
        self.assertIn("exceeds policy limit", decision.reason)


if __name__ == "__main__":
    unittest.main()
