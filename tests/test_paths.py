"""
Unit tests for AegisExec path validation and sensitive file protection.
Tests raw .. rejection, descriptor-relative O_NOFOLLOW resolution, sensitive credential paths,
and sanitized read-only workspace snapshot creation.
"""

import os
import shutil
import tempfile
import unittest

from aegisexec.paths import (
    PathValidator,
    PathValidationError,
    validate_raw_path_string,
    create_sanitized_workspace_snapshot,
    SnapshotError,
)


class TestPaths(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="aegis_test_workspace_")
        self.validator = PathValidator(workspace_root=self.temp_dir)

        # Create benign test file
        self.benign_file = os.path.join(self.temp_dir, "benign.txt")
        with open(self.benign_file, "w", encoding="utf-8") as f:
            f.write("Hello Aegis")

        # Create subfolder
        self.subfolder = os.path.join(self.temp_dir, "nested")
        os.makedirs(self.subfolder, exist_ok=True)
        self.nested_file = os.path.join(self.subfolder, "deep.txt")
        with open(self.nested_file, "w", encoding="utf-8") as f:
            f.write("Nested Content")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_valid_relative_file_access(self):
        fd, rel = self.validator.open_relative_file_fd("benign.txt")
        try:
            self.assertTrue(fd > 0)
            self.assertEqual(rel, "benign.txt")
            content = os.read(fd, 1024).decode("utf-8")
            self.assertEqual(content, "Hello Aegis")
        finally:
            os.close(fd)

    def test_valid_nested_file_access(self):
        fd, rel = self.validator.open_relative_file_fd("nested/deep.txt")
        try:
            self.assertTrue(fd > 0)
            self.assertEqual(rel, "nested/deep.txt")
        finally:
            os.close(fd)

    def test_reject_traversal_double_dot_before_normalization(self):
        with self.assertRaises(PathValidationError) as ctx:
            validate_raw_path_string("../../etc/passwd")
        self.assertIn("Raw directory traversal token '..' detected", str(ctx.exception))

    def test_reject_absolute_path_outside_workspace(self):
        with self.assertRaises(PathValidationError) as ctx:
            validate_raw_path_string("/etc/shadow")
        self.assertIn("Absolute paths are forbidden", str(ctx.exception))

    def test_reject_sensitive_env_file(self):
        env_file = os.path.join(self.temp_dir, ".env")
        with open(env_file, "w") as f:
            f.write("SECRET_KEY=12345")

        with self.assertRaises(PathValidationError) as ctx:
            self.validator.open_relative_file_fd(".env")
        self.assertIn("sensitive", str(ctx.exception).lower())

    def test_reject_sensitive_ssh_key_name(self):
        ssh_file = os.path.join(self.temp_dir, "id_rsa")
        with open(ssh_file, "w") as f:
            f.write("PRIVATE_KEY")

        with self.assertRaises(PathValidationError) as ctx:
            self.validator.open_relative_file_fd("id_rsa")
        self.assertIn("sensitive", str(ctx.exception).lower())

    def test_reject_null_byte_injection(self):
        with self.assertRaises(PathValidationError) as ctx:
            validate_raw_path_string("benign.txt\0/evil")
        self.assertIn("Null byte", str(ctx.exception))

    def test_snapshot_creation_regular_files_only(self):
        snap_dir = create_sanitized_workspace_snapshot(workspace_root=self.temp_dir)
        try:
            self.assertTrue(os.path.exists(os.path.join(snap_dir, "benign.txt")))
            self.assertTrue(os.path.exists(os.path.join(snap_dir, "nested", "deep.txt")))
        finally:
            shutil.rmtree(snap_dir, ignore_errors=True)

    def test_snapshot_rejects_symlink_inside_workspace(self):
        link_target = os.path.join(self.temp_dir, "benign.txt")
        link_name = os.path.join(self.temp_dir, "symlink_file.txt")
        os.symlink(link_target, link_name)

        with self.assertRaises(SnapshotError) as ctx:
            create_sanitized_workspace_snapshot(workspace_root=self.temp_dir)
        self.assertIn("Symlink", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
