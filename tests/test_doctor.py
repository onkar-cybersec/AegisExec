"""
Unit tests for AegisExec Doctor diagnostic checks.
"""

import unittest
from aegisexec.doctor import run_doctor


class TestDoctor(unittest.TestCase):

    def test_doctor_structure_and_keys(self):
        rep = run_doctor()
        rep_dict = rep.to_dict()

        self.assertIn("all_passed", rep_dict)
        self.assertIn("checks", rep_dict)
        self.assertIn("platform", rep_dict)

        # Ensure checks include OS, Python, bwrap, namespaces, filesystem
        check_names = [c["name"] for c in rep.checks]
        self.assertTrue(any("Operating System" in n for n in check_names))
        self.assertTrue(any("Python Interpreter" in n for n in check_names))
        self.assertTrue(any("Bubblewrap" in n for n in check_names))

        for c in rep.checks:
            self.assertIn(c["status"], ("PASS", "FAIL"))
            self.assertTrue(isinstance(c["details"], str))


if __name__ == "__main__":
    unittest.main()
