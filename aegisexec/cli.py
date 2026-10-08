"""
Command Line Interface for AegisExec.
Defensive Linux AI-agent action broker.
Author: Built by onkar-cybersec
"""

from __future__ import annotations
import argparse
import json
import os
import sys
from typing import List, Optional

from aegisexec import __version__
from aegisexec.doctor import print_doctor_cli
from aegisexec.schemas import validate_json_string
from aegisexec.broker import AegisBroker
from aegisexec.manifest import ManifestManager
from aegisexec.report import generate_html_report, generate_json_report


def cmd_doctor(args: argparse.Namespace) -> int:
    """Run environment and sandbox prerequisites diagnostic."""
    passed = print_doctor_cli()
    return 0 if passed else 1


def cmd_init(args: argparse.Namespace) -> int:
    """Initialize AegisExec workspace with default policy, tools, and sample requests."""
    target_dir = os.path.abspath(args.directory)
    os.makedirs(target_dir, exist_ok=True)
    os.makedirs(os.path.join(target_dir, "requests"), exist_ok=True)
    os.makedirs(os.path.join(target_dir, "workspace"), exist_ok=True)

    # 1. Default Policy
    policy_path = os.path.join(target_dir, "policy.json")
    default_policy = {
        "schema_version": "1.0",
        "policy_id": "pol-strict-v1",
        "name": "Strict Workspace Isolation Policy",
        "description": "Default restrictive policy: read/list inside workspace, sandboxed python without network",
        "workspace_root": os.path.join(target_dir, "workspace"),
        "allowed_operations": ["read_text", "list_dir", "run_python"],
        "path_rules": {
            "allowed_subpaths": [],
            "denied_patterns": [".env", ".git", ".ssh", ".aws"],
            "max_file_read_bytes": 1048576,
        },
        "execution_rules": {
            "max_timeout_seconds": 15,
            "max_output_bytes": 65536,
            "max_memory_mb": 256,
            "allow_network": False,
        },
        "require_approval_for": [],
        "audit": {
            "enabled": True,
            "log_path": os.path.join(target_dir, "audit.jsonl"),
        },
    }
    with open(policy_path, "w", encoding="utf-8") as f:
        json.dump(default_policy, f, indent=2)

    # 2. Sample Tools Manifest
    tools_path = os.path.join(target_dir, "tools.json")
    default_tools = {
        "schema_version": "1.0",
        "manifest_id": "manifest-starter-v1",
        "tools": [
            {
                "name": "read_workspace_file",
                "description": "Reads safe text file located strictly within the workspace directory",
                "operation": "read_text",
                "parameters_schema": {
                    "path": {"type": "string", "description": "Relative file path inside workspace"}
                },
                "risk_level": "low"
            },
            {
                "name": "list_workspace_dir",
                "description": "Lists contents of directories within the authorized workspace",
                "operation": "list_dir",
                "parameters_schema": {
                    "path": {"type": "string", "description": "Relative directory path"}
                },
                "risk_level": "low"
            },
            {
                "name": "run_isolated_script",
                "description": "Runs restricted Python calculation inside Bubblewrap sandbox with zero network",
                "operation": "run_python",
                "parameters_schema": {
                    "code": {"type": "string", "description": "Python snippet"}
                },
                "risk_level": "medium"
            }
        ]
    }
    with open(tools_path, "w", encoding="utf-8") as f:
        json.dump(default_tools, f, indent=2)

    # 3. Baseline for tools
    baseline_path = os.path.join(target_dir, "baseline.json")
    baseline = ManifestManager.pin(tools_path)
    with open(baseline_path, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2)

    # 4. Sample Requests
    sample_read = {
        "schema_version": "1.0",
        "request_id": "req-read-001",
        "operation": "read_text",
        "parameters": {
            "path": "sample.txt"
        }
    }
    with open(os.path.join(target_dir, "requests", "valid_read.json"), "w", encoding="utf-8") as f:
        json.dump(sample_read, f, indent=2)

    # Create dummy sample file in workspace
    with open(os.path.join(target_dir, "workspace", "sample.txt"), "w", encoding="utf-8") as f:
        f.write("AegisExec workspace file. Safe to read.")

    sample_traversal = {
        "schema_version": "1.0",
        "request_id": "req-attack-traversal",
        "operation": "read_text",
        "parameters": {
            "path": "../../etc/passwd"
        }
    }
    with open(os.path.join(target_dir, "requests", "attack_traversal.json"), "w", encoding="utf-8") as f:
        json.dump(sample_traversal, f, indent=2)

    print(f"[+] Initialized AegisExec directory structure in: {target_dir}")
    print(f"    - Policy:   {policy_path}")
    print(f"    - Tools:    {tools_path}")
    print(f"    - Baseline: {baseline_path}")
    print(f"    - Workspace:{os.path.join(target_dir, 'workspace')}")
    print(f"    - Requests: {os.path.join(target_dir, 'requests')}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """Evaluate an action request against policy without running."""
    with open(args.request, "r", encoding="utf-8") as f:
        req_data = validate_json_string(f.read(1024 * 1024 + 1))

    broker = AegisBroker.from_policy_file(args.policy)
    decision = broker.check(req_data)

    print(json.dumps(decision.to_dict(), indent=2))
    return 0 if decision.status == "ALLOWED" else 2


def cmd_run(args: argparse.Namespace) -> int:
    """Evaluate and run action under Bubblewrap sandbox if allowed."""
    with open(args.request, "r", encoding="utf-8") as f:
        req_data = validate_json_string(f.read(1024 * 1024 + 1))

    broker = AegisBroker.from_policy_file(args.policy)
    execution_result = broker.run(req_data)

    print(json.dumps(execution_result, indent=2))

    if not execution_result.get("executed"):
        return 2  # Denied or execution failed
    result = execution_result.get('result') or {}
    if 'exit_code' in result and result['exit_code'] != 0:
        return 4
    return 0


def cmd_pin(args: argparse.Namespace) -> int:
    """Compute canonical SHA-256 baseline for a tool manifest."""
    baseline = ManifestManager.pin(args.tools)
    out_json = json.dumps(baseline, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out_json)
        print(f"[+] Baseline written to {args.output} (SHA256: {baseline['canonical_sha256']})")
    else:
        print(out_json)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify tool manifest against baseline and detect drift."""
    report = ManifestManager.verify(args.tools, args.baseline)
    print(json.dumps(report, indent=2))
    return 0 if report.get("matches_baseline") else 3


def cmd_report(args: argparse.Namespace) -> int:
    """Generate HTML or JSON audit report."""
    fmt = args.format.lower()
    if fmt == "html":
        content = generate_html_report(args.audit)
    else:
        content = generate_json_report(args.audit)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"[+] Audit report generated at: {args.output}")
    else:
        print(content)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegisexec",
        description="AegisExec: Defensive Linux AI-Agent Action Broker (Built by onkar-cybersec)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # doctor
    p_doctor = subparsers.add_parser("doctor", help="Check Linux kernel, Bubblewrap, and namespace prerequisites")
    p_doctor.set_defaults(func=cmd_doctor)

    # init
    p_init = subparsers.add_parser("init", help="Initialize workspace with policy, baseline, and samples")
    p_init.add_argument("--dir", "--directory", dest="directory", default=".", help="Target directory (default: current)")
    p_init.set_defaults(func=cmd_init)

    # check
    p_check = subparsers.add_parser("check", help="Evaluate request against policy without executing")
    p_check.add_argument("request", help="Path to action request JSON")
    p_check.add_argument("--policy", required=True, help="Path to policy JSON")
    p_check.set_defaults(func=cmd_check)

    # run
    p_run = subparsers.add_parser("run", help="Evaluate request and execute under Bubblewrap sandbox")
    p_run.add_argument("request", help="Path to action request JSON")
    p_run.add_argument("--policy", required=True, help="Path to policy JSON")
    p_run.set_defaults(func=cmd_run)

    # pin
    p_pin = subparsers.add_parser("pin", help="Generate canonical SHA-256 baseline for tool manifest")
    p_pin.add_argument("tools", help="Path to tools.json manifest")
    p_pin.add_argument("--output", "-o", help="Optional output path for baseline.json")
    p_pin.set_defaults(func=cmd_pin)

    # verify
    p_verify = subparsers.add_parser("verify", help="Verify tool manifest against baseline and detect drift")
    p_verify.add_argument("tools", help="Path to tools.json manifest")
    p_verify.add_argument("--baseline", required=True, help="Path to baseline.json file")
    p_verify.set_defaults(func=cmd_verify)

    # report
    p_report = subparsers.add_parser("report", help="Generate audit summary report from audit.jsonl")
    p_report.add_argument("audit", help="Path to audit.jsonl log")
    p_report.add_argument("--format", choices=["html", "json"], default="html", help="Report format (default: html)")
    p_report.add_argument("--output", "-o", help="Optional output file path")
    p_report.set_defaults(func=cmd_report)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.subcommand:
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
