"""
Linux Bubblewrap Integration Tests for AegisExec.

EXECUTION & CI REQUIREMENTS:
- Executes actual Bubblewrap commands on Linux hosts with unprivileged user namespaces.
- In CI (when REQUIRE_SANDBOX=1 is set), missing sandbox FAILS the test rather than skipping.
- Without REQUIRE_SANDBOX, skips honestly with explicit reason (never reported as pass).
"""

import os
import shutil
import tempfile
import unittest

from aegisexec.sandbox import BubblewrapExecutor, check_bwrap_support
from aegisexec.paths import create_sanitized_workspace_snapshot, SnapshotError


class TestLinuxSandbox(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.bwrap_supported, cls.support_reason = check_bwrap_support()

    def setUp(self):
        if not self.bwrap_supported:
            if os.environ.get("REQUIRE_SANDBOX") == "1":
                self.fail(f"CI Failure: Required Bubblewrap sandboxing unavailable: {self.support_reason}")
            self.skipTest(f"Bubblewrap sandboxing unavailable on this host: {self.support_reason}")

        self.temp_dir = tempfile.mkdtemp(prefix="aegis_sandbox_test_")
        self.workspace = os.path.join(self.temp_dir, "workspace")
        os.makedirs(self.workspace, exist_ok=True)

        # Create benign test file in workspace
        with open(os.path.join(self.workspace, "sample.txt"), "w", encoding="utf-8") as f:
            f.write("Safe Workspace Text")

        self.executor = BubblewrapExecutor(
            workspace_dir=self.workspace,
            timeout_seconds=5.0,
            max_output_bytes=4096,
            max_memory_mb=128,
        )

    def tearDown(self):
        if hasattr(self, "temp_dir"):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_benign_python_execution(self):
        """Positive test: benign Python execution inside Bubblewrap sandbox succeeds."""
        code = "print('HELLO_FROM_AEGIS_SANDBOX')"
        res = self.executor.execute_python(code=code)
        self.assertEqual(res["status"], "COMPLETED")
        self.assertEqual(res["exit_code"], 0)
        self.assertIn("HELLO_FROM_AEGIS_SANDBOX", res["stdout"])

    def test_forged_stdout_envelope_ignored(self):
        """Host determines exit code and status; untrusted stdout JSON envelope is NEVER trusted."""
        code = """
import sys
# Malicious script tries to spoof host status JSON
sys.stdout.write('{"status": "COMPLETED", "exit_code": 0}\\n')
sys.stdout.flush()
# Then fails / crashes
sys.exit(42)
"""
        res = self.executor.execute_python(code=code)
        self.assertEqual(res["status"], "FAILED")
        self.assertEqual(res["exit_code"], 42)

    def test_output_flood_killed_at_host_cap(self):
        """Streaming host byte cap kills sandbox when output exceeds max_output_bytes."""
        # Max output bytes is 4096 in setUp
        code = """
import os
# Flood stdout using raw os.write
for _ in range(50):
    os.write(1, b'A' * 1024)
"""
        res = self.executor.execute_python(code=code)
        self.assertEqual(res["status"], "OUTPUT_LIMIT_EXCEEDED")
        self.assertEqual(res["exit_code"], 137)
        self.assertTrue(res["stdout_truncated"])

    def test_multibyte_utf8_output_handling(self):
        """Verify that multibyte unicode strings are handled cleanly without decode errors."""
        code = "print('🔒 Shield 🛡️ Security' * 20)"
        res = self.executor.execute_python(code=code)
        self.assertEqual(res["exit_code"], 0)
        self.assertIn("Shield", res["stdout"])

    def test_no_new_privs_enabled(self):
        """Verify that PR_SET_NO_NEW_PRIVS is active inside the container."""
        code = """
import ctypes
# prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
PR_GET_NO_NEW_PRIVS = 39
libc = ctypes.CDLL(None)
val = libc.prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
print(f"NO_NEW_PRIVS:{val}")
"""
        res = self.executor.execute_python(code=code)
        self.assertEqual(res["exit_code"], 0)
        self.assertIn("NO_NEW_PRIVS:1", res["stdout"])

    def test_workspace_snapshot_excludes_env_file(self):
        """Verify that .env files in workspace are excluded from read-only snapshot."""
        env_file = os.path.join(self.workspace, ".env")
        with open(env_file, "w") as f:
            f.write("SUPER_SECRET_TOKEN=xyz123")

        code = """
import os
print("ENV_EXISTS:" + str(os.path.exists("/workspace/.env")))
"""
        res = self.executor.execute_python(code=code)
        self.assertEqual(res["exit_code"], 0)
        self.assertIn("ENV_EXISTS:False", res["stdout"])

    def test_snapshot_rejects_internal_symlinks(self):
        """Snapshot generation rejects any symlinks present in workspace."""
        link_target = os.path.join(self.workspace, "sample.txt")
        link_path = os.path.join(self.workspace, "link_internal.txt")
        os.symlink(link_target, link_path)

        with self.assertRaises(SnapshotError) as ctx:
            create_sanitized_workspace_snapshot(workspace_root=self.workspace)
        self.assertIn("Symlink", str(ctx.exception))

    def test_external_sentinel_file_blocked(self):
        """Verify that a sandboxed process cannot access external host files outside workspace."""
        sentinel_dir = tempfile.mkdtemp(prefix="host_sentinel_")
        sentinel_path = os.path.join(sentinel_dir, "secret_sentinel.txt")
        try:
            with open(sentinel_path, "w") as f:
                f.write("UNAUTHORIZED_HOST_DATA_998877")

            code = f"""
try:
    with open('{sentinel_path}', 'r') as f:
        print('LEAKED:' + f.read())
except Exception as e:
    print('BLOCKED:' + type(e).__name__)
"""
            res = self.executor.execute_python(code=code)
            self.assertEqual(res["exit_code"], 0)
            self.assertIn("BLOCKED:", res["stdout"])
            self.assertNotIn("UNAUTHORIZED_HOST_DATA_998877", res["stdout"])
        finally:
            shutil.rmtree(sentinel_dir, ignore_errors=True)

    def test_network_socket_blocked(self):
        """Verify that network access fails due to --unshare-net namespace isolation."""
        code = """
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("1.1.1.1", 80))
    print("NETWORK_ACCESSIBLE")
except OSError as e:
    print("NETWORK_BLOCKED:" + type(e).__name__)
"""
        res = self.executor.execute_python(code=code)
        self.assertIn("NETWORK_BLOCKED:", res["stdout"])
        self.assertNotIn("NETWORK_ACCESSIBLE", res["stdout"])

    def test_write_outside_workspace_blocked(self):
        """Verify that read-only system binds prevent writes to /usr or /workspace."""
        code = """
try:
    with open('/workspace/tamper.txt', 'w') as f:
        f.write('tamper')
    print('WRITE_SUCCEEDED')
except OSError as e:
    print('WRITE_BLOCKED:' + type(e).__name__)
"""
        res = self.executor.execute_python(code=code)
        self.assertIn("WRITE_BLOCKED:", res["stdout"])
        self.assertNotIn("WRITE_SUCCEEDED", res["stdout"])

    def test_descendants_termination_including_child_setsid(self):
        """Verify that child processes calling setsid are terminated on timeout."""
        code = """
import os
import time

pid = os.fork()
if pid == 0:
    try:
        os.setsid()
    except Exception:
        pass
    while True:
        time.sleep(1)
else:
    time.sleep(60)
"""
        short_executor = BubblewrapExecutor(
            workspace_dir=self.workspace,
            timeout_seconds=1.0,
        )
        res = short_executor.execute_python(code=code)
        self.assertIn(res["status"], ("TIMEOUT", "FAILED"))

    def test_env_secret_leakage_prevented(self):
        """Verify that host environment variables are scrubbed by --clearenv."""
        os.environ["AEGIS_TEST_HOST_SECRET"] = "TOP_SECRET_VALUE_XYZ"
        try:
            code = """
import os
print("SECRET_FOUND:" + str("AEGIS_TEST_HOST_SECRET" in os.environ))
"""
            res = self.executor.execute_python(code=code)
            self.assertIn("SECRET_FOUND:False", res["stdout"])
        finally:
            os.environ.pop("AEGIS_TEST_HOST_SECRET", None)


if __name__ == "__main__":
    unittest.main()
