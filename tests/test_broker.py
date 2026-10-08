"""
Unit tests for AegisBroker coordinator.
Tests check, run, and audit generation for read_text and list_dir operations.
"""

import json
import os
import shutil
import tempfile
import unittest

from aegisexec.broker import AegisBroker


class TestBroker(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="aegis_broker_test_")
        self.workspace = os.path.join(self.temp_dir, "workspace")
        os.makedirs(self.workspace, exist_ok=True)

        self.audit_file = os.path.join(self.temp_dir, "audit.jsonl")

        # Create files
        self.hello_file = os.path.join(self.workspace, "hello.txt")
        with open(self.hello_file, "w", encoding="utf-8") as f:
            f.write("Hello from workspace")

        # Create subfolder
        self.subdir = os.path.join(self.workspace, "data")
        os.makedirs(self.subdir, exist_ok=True)
        with open(os.path.join(self.subdir, "file1.txt"), "w") as f:
            f.write("F1")

        self.policy = {
            "schema_version": "1.0",
            "policy_id": "pol-broker-test",
            "name": "Broker Test Policy",
            "workspace_root": self.workspace,
            "allowed_operations": ["read_text", "list_dir"],
            "path_rules": {
                "allowed_subpaths": [],
                "denied_patterns": [".env"],
                "max_file_read_bytes": 1024,
            },
            "audit": {
                "enabled": True,
                "log_path": self.audit_file,
            },
        }
        self.broker = AegisBroker(self.policy)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_run_read_text_success(self):
        req = {
            "schema_version": "1.0",
            "request_id": "req-read-ok",
            "operation": "read_text",
            "parameters": {"path": "hello.txt"},
        }
        res = self.broker.run(req)
        self.assertTrue(res["executed"])
        self.assertEqual(res["result"]["content"], "Hello from workspace")
        self.assertEqual(res["decision"]["status"], "ALLOWED")

        # Verify audit file logged
        self.assertTrue(os.path.exists(self.audit_file))
        with open(self.audit_file, "r") as f:
            lines = f.readlines()
        self.assertTrue(len(lines) >= 1)

    def test_run_list_dir_success(self):
        req = {
            "schema_version": "1.0",
            "request_id": "req-list-ok",
            "operation": "list_dir",
            "parameters": {"path": "."},
        }
        res = self.broker.run(req)
        self.assertTrue(res["executed"])
        names = [entry["name"] for entry in res["result"]["entries"]]
        self.assertIn("hello.txt", names)
        self.assertIn("data", names)

    def test_run_traversal_denied_no_execution(self):
        req = {
            "schema_version": "1.0",
            "request_id": "req-traversal-deny",
            "operation": "read_text",
            "parameters": {"path": "../../../etc/passwd"},
        }
        res = self.broker.run(req)
        self.assertFalse(res["executed"])
        self.assertEqual(res["decision"]["status"], "DENIED")
        self.assertIsNone(res["result"])
        self.assertIn("traversal", res["error"].lower())


if __name__ == "__main__":
    unittest.main()
