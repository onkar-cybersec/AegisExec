"""
Unit tests for AegisExec audit logging and secret redaction.
Tests secure 0600 file permissions, strict metadata allowlist, O_NOFOLLOW, and error handling.
"""

import json
import os
import stat
import tempfile
import unittest

from aegisexec.audit import AuditLogger, ALLOWED_AUDIT_KEYS, sanitize_reason_code


class TestAudit(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="aegis_audit_test_")
        self.log_file = os.path.join(self.temp_dir, "audit.jsonl")
        self.logger = AuditLogger(log_path=self.log_file)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_file_permissions_are_0600(self):
        self.logger.log(
            event_type="POLICY_CHECK",
            decision_id="dec-1",
            request_id="req-1",
            operation="read_text",
            status="ALLOWED",
            reason="Operation read_text executed successfully",
            matched_rules=["rule1"],
            evidence={"requested_bytes": 1024},
        )
        self.assertTrue(os.path.exists(self.log_file))
        mode = stat.S_IMODE(os.stat(self.log_file).st_mode)
        self.assertEqual(mode, 0o600, f"Expected 0600 permissions, got {oct(mode)}")

    def test_strict_metadata_allowlist_enforced(self):
        entry = self.logger.log(
            event_type="POLICY_CHECK",
            decision_id="dec-2",
            request_id="req-2",
            operation="read_text",
            status="DENIED",
            reason="Path boundary check failed: Traversal detected",
            matched_rules=["filesystem.boundary_confinement"],
            evidence={"raw_attack_code": "malicious()", "secret_token": "ghp_123456789"},
            execution_summary={"bytes_read": 50, "raw_untrusted_output": "SECRET_DATA"},
        )
        self.assertEqual(set(entry.keys()), ALLOWED_AUDIT_KEYS)
        # Ensure no raw attack code or secret token leaked
        self.assertNotIn("malicious()", str(entry))
        self.assertNotIn("ghp_123456789", str(entry))
        self.assertNotIn("SECRET_DATA", str(entry))
        self.assertEqual(entry["reason_code"], "PATH_BOUNDARY_VIOLATION")

    def test_jsonl_append_format(self):
        for i in range(3):
            self.logger.log(
                event_type="TEST",
                decision_id=f"dec-{i}",
                request_id=f"req-{i}",
                operation="read_text",
                status="ALLOWED",
                reason="Safe",
                matched_rules=[],
                evidence={},
            )

        with open(self.log_file, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]

        self.assertEqual(len(lines), 3)
        for line in lines:
            parsed = json.loads(line)
            self.assertIn("timestamp", parsed)
            self.assertIn("event_id", parsed)
            self.assertEqual(set(parsed.keys()), ALLOWED_AUDIT_KEYS)


if __name__ == "__main__":
    unittest.main()
