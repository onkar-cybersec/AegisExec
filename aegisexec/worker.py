"""
Trusted Execution Worker Harness for AegisExec.
Executed strictly inside the Linux Bubblewrap sandbox.

SECURITY CONSTRAINTS:
- No shell invocation.
- Process-level resource limits set before code execution; fails closed if limit setup fails.
- Direct script execution with sys.argv bound; stdout/stderr streams to host descriptors
  where host-authoritative streaming byte caps and exit codes are enforced.
"""

from __future__ import annotations
import argparse
import os
import resource
import sys
from typing import NoReturn


def enforce_sandbox_limits(max_mem_mb: int, cpu_seconds: int) -> None:
    """Set process-level address space (virtual memory) limit via getrlimit/setrlimit."""
    try:
        if max_mem_mb > 0:
            mem_bytes = max_mem_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
        resource.setrlimit(resource.RLIMIT_NPROC, (128, 128))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception as exc:
        sys.stderr.write(f"[Worker Error: Failed to enforce memory limits: {exc}]\n")
        sys.exit(125)


def main() -> NoReturn:
    parser = argparse.ArgumentParser(description="AegisExec trusted in-sandbox worker harness")
    parser.add_argument("--code-file", type=str, help="Path to code file inside sandbox")
    parser.add_argument("--max-memory-mb", type=int, default=256, help="Maximum virtual memory in MB")
    parser.add_argument("--cpu-seconds", type=int, default=30)
    parser.add_argument("script_args", nargs="*", help="Arguments passed to script")

    args = parser.parse_args()

    # Enforce address space limit; fail closed if rlimit fails
    enforce_sandbox_limits(args.max_memory_mb, args.cpu_seconds)

    if args.code_file:
        try:
            with open(args.code_file, "r", encoding="utf-8") as f:
                code_text = f.read(1024 * 1024 + 1)
            if len(code_text.encode('utf-8')) > 1024 * 1024:
                sys.exit(126)
        except Exception as exc:
            sys.stderr.write(f"[Worker Error: Cannot read script file: {exc}]\n")
            sys.exit(126)
    else:
        code_text = sys.stdin.read()

    # Prepare isolated environment
    sys.argv = ["sandboxed_script"] + args.script_args

    sandbox_globals = {
        "__name__": "__main__",
        "__builtins__": __builtins__,
    }

    try:
        compiled = compile(code_text, "<sandboxed_python>", "exec")
        exec(compiled, sandbox_globals)
        sys.exit(0)
    except SystemExit as se:
        code = se.code if isinstance(se.code, int) else (0 if se.code is None else 1)
        sys.exit(code)
    except Exception:
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
