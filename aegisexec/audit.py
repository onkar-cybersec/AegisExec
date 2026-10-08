"""
Secure Sanitized Audit Logging for AegisExec.

AUDIT SAFETY DIRECTIVES:
- Strict metadata allowlist: NEVER log raw rejected inputs, raw file paths, raw code, or tokens.
- Secure file opening with O_NOFOLLOW and 0600 mode.
- JSON Lines (JSONL) format with bounded record sizes.
- Audit failures are NOT silently swallowed when audit is enabled.
"""

from __future__ import annotations
import datetime
import json
import os
import stat
import uuid
import hashlib
from typing import Any, Dict, List, Optional

ALLOWED_AUDIT_KEYS = frozenset({
    "timestamp",
    "event_id",
    "event_type",
    "decision_id",
    "request_id",
    "operation",
    "status",
    "reason_code",
    "matched_rules",
    "metrics",
})


class AuditError(Exception):
    """Raised when audit logging fails."""
    pass


def sanitize_reason_code(reason: str) -> str:
    """Extract a safe, generic categorization from a reason string without leaking inputs."""
    if not isinstance(reason, str):
        return "UNKNOWN_REASON"
    reason_clean = reason.replace("\n", " ").replace("\r", " ").strip()
    # Strip any potential tokens or quotes
    if "Path boundary" in reason_clean or "traversal" in reason_clean:
        return "PATH_BOUNDARY_VIOLATION"
    if "sensitive" in reason_clean:
        return "SENSITIVE_TARGET_DENIED"
    if "schema" in reason_clean.lower():
        return "SCHEMA_VALIDATION_FAILURE"
    if "allowed_operations" in reason_clean:
        return "OPERATION_NOT_PERMITTED"
    if "approval" in reason_clean.lower():
        return "APPROVAL_REQUIREMENT_DENIED"
    if "timeout" in reason_clean.lower():
        return "TIMEOUT_LIMIT_EXCEEDED"
    if "Sandboxing unavailable" in reason_clean:
        return "SANDBOX_PREREQUISITE_FAILURE"
    if "successfully" in reason_clean.lower():
        return "OPERATION_SUCCESS"
    # Fallback to bounded length generic string
    return 'POLICY_OR_EXECUTION_RESULT'


def sanitize_metrics(evidence: Optional[Dict[str, Any]], execution_summary: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Extract only approved scalar operational metrics."""
    metrics: Dict[str, Any] = {}

    if isinstance(evidence, dict):
        if "requested_bytes" in evidence and isinstance(evidence["requested_bytes"], int):
            metrics["requested_bytes"] = evidence["requested_bytes"]
        if "timeout_seconds" in evidence and isinstance(evidence["timeout_seconds"], (int, float)):
            metrics["timeout_seconds"] = evidence["timeout_seconds"]

    if isinstance(execution_summary, dict):
        if "bytes_read" in execution_summary and isinstance(execution_summary["bytes_read"], int):
            metrics["bytes_read"] = execution_summary["bytes_read"]
        if "sha256_prefix" in execution_summary and isinstance(execution_summary["sha256_prefix"], str):
            metrics["sha256_prefix"] = execution_summary["sha256_prefix"][:8]
        if "entry_count" in execution_summary and isinstance(execution_summary["entry_count"], int):
            metrics["entry_count"] = execution_summary["entry_count"]
        if "exit_code" in execution_summary and isinstance(execution_summary["exit_code"], int):
            metrics["exit_code"] = execution_summary["exit_code"]
        if "duration_ms" in execution_summary and isinstance(execution_summary["duration_ms"], (int, float)):
            metrics["duration_ms"] = execution_summary["duration_ms"]

    return metrics


class AuditLogger:
    """Appends strictly sanitized JSONL audit events with secure file permissions."""

    def __init__(self, log_path: Optional[str] = None):
        self.log_path = log_path

    def _open_log_fd(self, path: str) -> int:
        """Create directory and open file with O_NOFOLLOW and 0600 mode."""
        dir_path = os.path.dirname(os.path.abspath(path))
        if dir_path and not os.path.exists(dir_path):
            os.makedirs(dir_path, mode=0o700, exist_ok=True)

        flags = os.O_CREAT | os.O_WRONLY | os.O_APPEND | os.O_NONBLOCK
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        fd = os.open(path, flags, 0o600)
        # Ensure mode is strictly 0600
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise AuditError('Audit target must be a regular unlinked-alias-free file')
            os.fchmod(fd, 0o600)
        except BaseException:
            os.close(fd)
            raise
        return fd

    def log(
        self,
        event_type: str,
        decision_id: str,
        request_id: str,
        operation: str,
        status: str,
        reason: str,
        matched_rules: list[str],
        evidence: Optional[Dict[str, Any]] = None,
        execution_summary: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Construct strictly sanitized audit record and write to JSONL log."""
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        event_id = f"aud-{uuid.uuid4().hex[:12]}"

        # Strictly allowlisted fields only
        entry = {
            "timestamp": timestamp,
            "event_id": event_id,
            "event_type": str(event_type)[:32],
            "decision_id": str(decision_id)[:32],
            "request_id": hashlib.sha256(str(request_id).encode('utf-8')).hexdigest()[:24],
            "operation": operation if operation in ('read_text', 'list_dir', 'run_python') else 'unknown',
            "status": str(status)[:32],
            "reason_code": sanitize_reason_code(reason),
            "matched_rules": [str(r)[:64] for r in (matched_rules or [])][:10],
            "metrics": sanitize_metrics(evidence, execution_summary),
        }

        if self.log_path:
            try:
                fd = self._open_log_fd(self.log_path)
                try:
                    line = (json.dumps(entry, separators=(",", ":")) + "\n").encode("utf-8")
                    written = os.write(fd, line)
                    if written != len(line):
                        raise AuditError("Short write during audit log append")
                finally:
                    os.close(fd)
            except Exception as exc:
                raise AuditError(f"Failed to write audit entry to '{self.log_path}': {exc}") from exc

        return entry
