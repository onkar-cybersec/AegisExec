"""
Core Action Broker for AegisExec.
Mediates all agent requests, evaluates policy, enforces containment,
and routes allowed executions through bubblewrap isolation.
"""

from __future__ import annotations
import hashlib
import os
import stat
from typing import Any, Dict, List, Optional
from aegisexec.schemas import validate_json_string
from aegisexec.policy import PolicyEngine, PolicyDecision
from aegisexec.sandbox import BubblewrapExecutor, SandboxPrerequisiteError, SandboxError
from aegisexec.audit import AuditLogger
from aegisexec.paths import PathValidationError


class AegisBroker:
    """
    Trusted local broker serving as the sole execution gateway for supported actions.
    """

    def __init__(self, policy_data: Dict[str, Any]):
        self.policy_engine = PolicyEngine(policy_data)
        self.workspace_root = self.policy_engine.workspace_root
        audit_cfg = self.policy_engine.validated_policy.get("audit", {})
        log_path = audit_cfg.get("log_path") if audit_cfg.get("enabled", True) else None
        self.audit_logger = AuditLogger(log_path=log_path)

    @classmethod
    def from_policy_file(cls, policy_path: str) -> "AegisBroker":
        # Bounded file read before parsing JSON (max 1 MB)
        with open(policy_path, "r", encoding="utf-8") as f:
            raw = f.read(1024 * 1024 + 1)
        if len(raw.encode("utf-8")) > 1024 * 1024:
            raise ValueError("Policy file exceeds maximum allowed size of 1MB")
        policy_data = validate_json_string(raw)
        return cls(policy_data)

    def check(self, request_data: Any) -> PolicyDecision:
        """
        Evaluate request against policy without performing execution.
        """
        decision = self.policy_engine.evaluate(request_data)
        req_id = request_data.get("request_id", "unknown") if isinstance(request_data, dict) and isinstance(request_data.get("request_id"), str) else "unknown"

        self.audit_logger.log(
            event_type="POLICY_CHECK",
            decision_id=decision.decision_id,
            request_id=req_id,
            operation=decision.operation,
            status=decision.status,
            reason=decision.reason,
            matched_rules=decision.matched_rules,
            evidence=decision.evidence,
        )
        return decision

    def run(self, request_data: Any) -> Dict[str, Any]:
        """
        Evaluate policy and execute operation if allowed.
        Fails closed on any denial, boundary error, or sandbox refusal.
        """
        decision = self.check(request_data)

        if decision.status != "ALLOWED":
            return {
                "decision": decision.to_dict(),
                "executed": False,
                "result": None,
                "error": decision.reason,
            }

        op = decision.operation
        params = request_data.get("parameters", {}) if isinstance(request_data, dict) else {}
        req_id = request_data.get("request_id", "unknown") if isinstance(request_data, dict) and isinstance(request_data.get("request_id"), str) else "unknown"

        execution_summary: Dict[str, Any] = {}
        result_payload: Dict[str, Any] = {}
        execution_error: Optional[str] = None

        try:
            if op == "read_text":
                target_path = params.get("path", "")
                max_bytes = params.get("max_bytes", self.policy_engine.max_file_read_bytes)
                max_allowed = min(max_bytes, self.policy_engine.max_file_read_bytes)

                # Open via descriptor-relative O_NOFOLLOW; fstat verified regular file
                fd, display_path = self.policy_engine.path_validator.open_relative_file_fd(target_path)
                try:
                    # Binary bounded read (max_allowed + 1 bytes to detect truncation)
                    raw_bytes = os.read(fd, max_allowed + 1)
                finally:
                    os.close(fd)

                is_truncated = len(raw_bytes) > max_allowed
                content_bytes = raw_bytes[:max_allowed]
                content = content_bytes.decode("utf-8", errors="ignore")
                h = hashlib.sha256(content_bytes).hexdigest()

                result_payload = {
                    "content": content,
                    "bytes_read": len(content_bytes),
                    "sha256": h,
                    "truncated": is_truncated,
                }
                execution_summary = {
                    "bytes_read": len(content_bytes),
                    "sha256_prefix": h[:8],
                    "truncated": is_truncated,
                }

            elif op == "list_dir":
                target_path = params.get("path", ".")
                max_depth = params.get("max_depth", 1)
                include_hidden = params.get("include_hidden", False)

                entries = self.policy_engine.path_validator.list_dir_bounded(
                    target_path=target_path,
                    max_depth=max_depth,
                    include_hidden=include_hidden,
                )

                result_payload = {
                    "entries": entries,
                    "count": len(entries),
                }
                execution_summary = {"entry_count": len(entries)}

            elif op == "run_python":
                exec_rules = self.policy_engine.execution_rules
                timeout = params.get("timeout_seconds", exec_rules.get("max_timeout_seconds", 30))
                max_output = exec_rules.get("max_output_bytes", 65536)
                max_mem = exec_rules.get("max_memory_mb", 256)

                sandbox = BubblewrapExecutor(
                    workspace_dir=self.workspace_root,
                    timeout_seconds=timeout,
                    max_output_bytes=max_output,
                    max_memory_mb=max_mem,
                    allowed_subpaths=self.policy_engine.allowed_subpaths,
                    denied_patterns=self.policy_engine.denied_patterns,
                )

                code = params.get("code")
                script_path = params.get("script_path")
                script_args = params.get("args")

                run_res = sandbox.execute_python(
                    code=code,
                    script_workspace_rel_path=script_path,
                    script_args=script_args,
                )

                result_payload = run_res
                execution_summary = {
                    "status": run_res.get("status"),
                    "exit_code": run_res.get("exit_code"),
                    "duration_ms": run_res.get("duration_ms"),
                    "sandbox_enforced": run_res.get('sandbox_enforced', False),
                }

        except (PathValidationError, SandboxPrerequisiteError, SandboxError) as err:
            execution_error = str(err)
            execution_summary = {"error": type(err).__name__, "reason": str(err)}
        except Exception as exc:
            execution_error = f"Execution error: {exc}"
            execution_summary = {"error": type(exc).__name__}

        # Log audit entry
        self.audit_logger.log(
            event_type="OPERATION_EXECUTION",
            decision_id=decision.decision_id,
            request_id=req_id,
            operation=op,
            status="EXECUTED" if not execution_error else "EXECUTION_FAILED",
            reason=execution_error or f"Operation {op} executed successfully",
            matched_rules=decision.matched_rules,
            evidence=decision.evidence,
            execution_summary=execution_summary,
        )

        return {
            "decision": decision.to_dict(),
            "executed": execution_error is None,
            "result": result_payload if not execution_error else None,
            "error": execution_error,
        }
