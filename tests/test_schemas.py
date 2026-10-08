"""
Unit tests for AegisExec JSON schema validation and regression tests.
Tests duplicate JSON keys, bool-as-int coercion prevention, NaN/Infinity,
non-dict roots, bounded strings/args, and hard policy limits.
"""

import json
import unittest

from aegisexec.schemas import (
    validate_action_request,
    validate_policy,
    validate_tool_manifest,
    validate_json_string,
    SchemaValidationError,
    MAX_JSON_BYTES,
    POLICY_HARD_MAX_TIMEOUT_SECONDS,
)


class TestSchemas(unittest.TestCase):

    def test_valid_action_request_read(self):
        req = {
            "schema_version": "1.0",
            "request_id": "req-001",
            "operation": "read_text",
            "parameters": {
                "path": "data/log.txt",
                "max_bytes": 1024,
            },
        }
        res = validate_action_request(req)
        self.assertEqual(res["operation"], "read_text")

    def test_reject_duplicate_json_keys(self):
        raw_json = '{"schema_version": "1.0", "request_id": "r1", "operation": "read_text", "parameters": {"path": "a"}, "parameters": {"path": "b"}}'
        with self.assertRaises(SchemaValidationError) as ctx:
            validate_json_string(raw_json)
        self.assertIn("Duplicate JSON key", str(ctx.exception))

    def test_reject_non_dict_root(self):
        for bad_root in (["item"], "string", 123, True):
            with self.assertRaises(SchemaValidationError):
                validate_action_request(bad_root)

    def test_reject_list_or_dict_as_operation_without_type_error(self):
        req = {
            "schema_version": "1.0",
            "request_id": "req-002",
            "operation": ["read_text"],
            "parameters": {"path": "file.txt"},
        }
        with self.assertRaises(SchemaValidationError) as ctx:
            validate_action_request(req)
        self.assertIn("must be string", str(ctx.exception))

    def test_reject_list_or_dict_as_version_without_type_error(self):
        req = {
            "schema_version": {"version": "1.0"},
            "request_id": "req-003",
            "operation": "read_text",
            "parameters": {"path": "file.txt"},
        }
        with self.assertRaises(SchemaValidationError) as ctx:
            validate_action_request(req)
        self.assertIn("must be string", str(ctx.exception))

    def test_reject_bool_as_numeric(self):
        # In Python, isinstance(True, int) is True! AegisExec must reject bool for max_bytes or timeout
        req = {
            "schema_version": "1.0",
            "request_id": "req-bool-bytes",
            "operation": "read_text",
            "parameters": {
                "path": "file.txt",
                "max_bytes": True,  # Bool passed as int
            },
        }
        with self.assertRaises(SchemaValidationError) as ctx:
            validate_action_request(req)
        self.assertIn("must be a positive integer", str(ctx.exception))

    def test_reject_nan_and_infinity_in_timeout(self):
        req_nan = {
            "schema_version": "1.0",
            "request_id": "req-nan",
            "operation": "run_python",
            "parameters": {
                "code": "print(1)",
                "timeout_seconds": float("nan"),
            },
        }
        with self.assertRaises(SchemaValidationError) as ctx:
            validate_action_request(req_nan)
        self.assertTrue(str(ctx.exception))

        req_inf = {
            "schema_version": "1.0",
            "request_id": "req-inf",
            "operation": "run_python",
            "parameters": {
                "code": "print(1)",
                "timeout_seconds": float("inf"),
            },
        }
        with self.assertRaises(SchemaValidationError) as ctx:
            validate_action_request(req_inf)
        self.assertTrue(str(ctx.exception))

    def test_reject_timeout_exceeding_hard_upper_bound(self):
        req = {
            "schema_version": "1.0",
            "request_id": "req-huge-timeout",
            "operation": "run_python",
            "parameters": {
                "code": "print(1)",
                "timeout_seconds": POLICY_HARD_MAX_TIMEOUT_SECONDS + 10,
            },
        }
        with self.assertRaises(SchemaValidationError) as ctx:
            validate_action_request(req)
        self.assertIn("exceeds hard maximum", str(ctx.exception))

    def test_reject_unknown_field_in_request(self):
        req = {
            "schema_version": "1.0",
            "request_id": "req-002",
            "operation": "read_text",
            "parameters": {"path": "file.txt"},
            "unauthorized_injection_field": "exploit",
        }
        with self.assertRaises(SchemaValidationError) as ctx:
            validate_action_request(req)
        self.assertIn("unauthorized_injection_field", str(ctx.exception))

    def test_reject_unknown_field_in_parameters(self):
        req = {
            "schema_version": "1.0",
            "request_id": "req-003",
            "operation": "read_text",
            "parameters": {
                "path": "file.txt",
                "shell_command": "rm -rf /",
            },
        }
        with self.assertRaises(SchemaValidationError) as ctx:
            validate_action_request(req)
        self.assertIn("shell_command", str(ctx.exception))

    def test_reject_oversized_payload(self):
        giant_string = "A" * (MAX_JSON_BYTES + 50)
        raw = json.dumps({"schema_version": "1.0", "data": giant_string})
        with self.assertRaises(SchemaValidationError) as ctx:
            validate_json_string(raw, max_bytes=MAX_JSON_BYTES)
        self.assertIn("exceeds maximum allowed", str(ctx.exception))

    def test_reject_policy_allowing_network_in_v1(self):
        pol = {
            "schema_version": "1.0",
            "policy_id": "pol-bad-net",
            "name": "Bad Network Policy",
            "workspace_root": "/tmp/workspace",
            "allowed_operations": ["run_python"],
            "execution_rules": {
                "allow_network": True,
            },
        }
        with self.assertRaises(SchemaValidationError) as ctx:
            validate_policy(pol)
        self.assertIn("allow_network", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
