"""
System Environment and Bubblewrap Sandbox Diagnostic (aegisexec doctor).

Inspects host kernel, Bubblewrap availability, user namespace support,
and Python interpreter runtime to verify whether the host is capable of
enforcing isolated execution.
"""

from __future__ import annotations
import os
import platform
import shutil
import subprocess
import sys
from typing import Dict, Any, List

FIXED_BWRAP_PATH = "/usr/bin/bwrap"


class DoctorReport:
    def __init__(self):
        self.checks: List[Dict[str, Any]] = []

    def add_check(self, name: str, passed: bool, details: str, remediation: str = ""):
        self.checks.append({
            "name": name,
            "status": "PASS" if passed else "FAIL",
            "details": details,
            "remediation": remediation,
        })

    def is_all_passed(self) -> bool:
        return all(c["status"] == "PASS" for c in self.checks)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "all_passed": self.is_all_passed(),
            "checks": self.checks,
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
                "python": sys.version.split()[0],
            }
        }


def run_doctor() -> DoctorReport:
    """Run comprehensive host environment checks."""
    report = DoctorReport()

    # 1. OS check
    is_linux = sys.platform.startswith("linux")
    report.add_check(
        name="Operating System: Linux",
        passed=is_linux,
        details=f"Current OS: {platform.system()} ({platform.release()})",
        remediation="AegisExec sandboxed execution requires a Linux host (e.g. Kali, Parrot, Ubuntu, Debian).",
    )

    # 2. Python version check (tested on Python 3.10)
    py_ver = sys.version_info
    py_ok = (py_ver.major == 3 and py_ver.minor >= 10)
    report.add_check(
        name="Python Interpreter >= 3.10",
        passed=py_ok,
        details=f"Detected Python {py_ver.major}.{py_ver.minor}.{py_ver.micro}",
        remediation="Install Python 3.10 or higher.",
    )

    # 3. Bubblewrap binary check
    bwrap_path = None
    if os.path.exists(FIXED_BWRAP_PATH) and os.access(FIXED_BWRAP_PATH, os.X_OK):
        bwrap_path = FIXED_BWRAP_PATH
    else:
        bwrap_path = shutil.which("bwrap")

    if bwrap_path:
        try:
            res = subprocess.run([bwrap_path, "--version"], capture_output=True, text=True, timeout=3)
            bwrap_ver = res.stdout.strip() or "Installed"
            report.add_check(
                name="Bubblewrap (bwrap) Binary",
                passed=True,
                details=f"Located at {bwrap_path} ({bwrap_ver})",
            )
        except Exception as exc:
            report.add_check(
                name="Bubblewrap (bwrap) Binary",
                passed=False,
                details=f"Located at {bwrap_path} but execution failed: {exc}",
                remediation="Ensure bwrap has executable permissions.",
            )
    else:
        report.add_check(
            name="Bubblewrap (bwrap) Binary",
            passed=False,
            details=f"bwrap not found at {FIXED_BWRAP_PATH} or in PATH",
            remediation="Install via: sudo apt-get update && sudo apt-get install -y bubblewrap",
        )

    # 4. User Namespaces & bwrap capability probe (with --new-session and no invalid flags)
    if is_linux and bwrap_path:
        probe_cmd = [
            bwrap_path,
            "--ro-bind", "/usr", "/usr",
            "--proc", "/proc",
            "--dev", "/dev",
            "--unshare-all",
            "--new-session",
        ]
        for sys_dir in ("/lib", "/lib64", "/bin"):
            if os.path.exists(sys_dir):
                probe_cmd.extend(["--ro-bind", sys_dir, sys_dir])
        probe_cmd.append("true")

        try:
            probe = subprocess.run(
                probe_cmd,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if probe.returncode == 0:
                report.add_check(
                    name="Unprivileged User Namespaces",
                    passed=True,
                    details="Bubblewrap successfully created unprivileged container namespaces",
                )
            else:
                err = probe.stderr.strip()
                hint = "Check kernel.unprivileged_userns_clone sysctl or apparmor namespace restrictions."
                if "No such file or directory" in err:
                    hint = "Check minimal mount paths or missing /usr subdirectories."
                report.add_check(
                    name="Unprivileged User Namespaces",
                    passed=False,
                    details=f"Namespace creation probe returned code {probe.returncode}: {err}",
                    remediation=f"Ensure unprivileged user namespaces are supported by kernel. {hint}",
                )
        except Exception as exc:
            report.add_check(
                name="Unprivileged User Namespaces",
                passed=False,
                details=f"Probe invocation error: {exc}",
                remediation="Ensure the host kernel permits namespace unsharing.",
            )
    else:
        report.add_check(
            name="Unprivileged User Namespaces",
            passed=False,
            details="Skipped because Linux or bwrap is not available",
            remediation="Ensure Linux and bubblewrap are present.",
        )

    # 5. Core directories probe
    core_dirs_ok = True
    missing = []
    for d in ("/usr", "/proc", "/dev", "/tmp"):
        if not os.path.exists(d):
            core_dirs_ok = False
            missing.append(d)

    report.add_check(
        name="Filesystem Mount Points",
        passed=core_dirs_ok,
        details=f"Essential mount targets verified (missing: {missing or 'none'})",
        remediation="Ensure standard Linux system directories exist.",
    )

    return report


def print_doctor_cli() -> bool:
    """Print human-readable doctor status to console."""
    rep = run_doctor()
    print("=" * 65)
    print("  AegisExec System Environment & Isolation Doctor")
    print("=" * 65)
    print(f"  OS:      {rep.to_dict()['platform']['system']} {rep.to_dict()['platform']['release']}")
    print(f"  Python:  {rep.to_dict()['platform']['python']}")
    print("-" * 65)

    for c in rep.checks:
        symbol = "[PASS]" if c["status"] == "PASS" else "[FAIL]"
        print(f" {symbol:6} {c['name']}")
        print(f"        Details:     {c['details']}")
        if c["status"] == "FAIL" and c["remediation"]:
            print(f"        Remediation: {c['remediation']}")
        print()

    print("-" * 65)
    if rep.is_all_passed():
        print("  Status: READY - Host meets all Bubblewrap sandboxing requirements.")
    else:
        print("  Status: DEGRADED - Sandboxed execution (run_python) will fail-closed.")
        print("  Note: 'check' policy evaluations and tool 'pin'/'verify' remain functional.")
    print("=" * 65)
    return rep.is_all_passed()
