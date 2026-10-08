"""
Policy Evaluation Engine for AegisExec.
Evaluates structured ActionRequests against local policy rules with default-deny semantics.
Produces stable decision objects containing decision_id, status, matched_rules,
reason, remediation, and sanitized evidence.
"""

from __future__ import annotations
import hashlib
import uuid
from typing import Any, Dict, List, Optional
from aegisexec.schemas import validate_action_request, validate_policy, SchemaValidationError
from aegisexec.paths import PathValidator, PathValidationError, validate_raw_path_string, is_sensitive_name


class PolicyDecision:
    """Represents the outcome of policy evaluation."""

    def __init__(
        self,
        decision_id: str,
        status: str,
        operation: str,
        reason: str,
        remediation: str,
        matched_rules: List[str],
        evidence: Dict[str, Any],
    ):
        self.decision_id = decision_id
        self.status = status  # "ALLOWED" or "DENIED"
        self.operation = operation
        self.reason = reason
        self.remediation = remediation
        self.matched_rules = matched_rules
        self.evidence = evidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "status": self.status,
            "operation": self.operation,
            "reason": self.reason,
            "remediation": self.remediation,
            "matched_rules": self.matched_rules,
            "evidence": self.evidence,
        }


class PolicyEngine:
    """Evaluates ActionRequests against Policy rules."""

    def __init__(self, policy: Dict[str, Any]):
        self.raw_policy = policy
        self.validated_policy = validate_policy(policy)
        self.policy_id = self.validated_policy["policy_id"]
        self.workspace_root = self.validated_policy["workspace_root"]
        self.allowed_operations = set(self.validated_policy["allowed_operations"])

        path_rules = self.validated_policy.get("path_rules", {})
        self.allowed_subpaths = path_rules.get("allowed_subpaths", [])
        self.denied_patterns = path_rules.get("denied_patterns", [])
        self.path_validator = PathValidator(
            workspace_root=self.workspace_root,
            allowed_subpaths=self.allowed_subpaths,
            denied_patterns=self.denied_patterns,
        )
        self.max_file_read_bytes = path_rules.get("max_file_read_bytes", 10 * 1024 * 1024)

        self.execution_rules = self.validated_policy.get("execution_rules", {})
        self.require_approval_for = set(self.validated_policy.get("require_approval_for", []))

    def _generate_decision_id(self, request_id: str, operation: str) -> str:
        h = hashlib.sha256(f"{self.policy_id}:{request_id}:{operation}".encode("utf-8")).hexdigest()
        return f"dec-{h[:12]}"

    def evaluate(self, request_data: Any) -> PolicyDecision:
        """
        Evaluate an action request against the policy.
        Always fails closed on validation or boundary errors.
        """
        try:
            req = validate_action_request(request_data)
        except SchemaValidationError as sve:
            op_label = request_data.get("operation", "unknown") if isinstance(request_data, dict) and isinstance(request_data.get("operation"), str) else "unknown"
            return PolicyDecision(
                decision_id=f"dec-err-{uuid.uuid4().hex[:8]}",
                status="DENIED",
                operation=op_label,
                reason=f"ActionRequest failed schema validation: {sve}",
                remediation="Ensure the action request strictly adheres to AegisExec schema v1.0, has no extra fields, and uses valid scalar types.",
                matched_rules=["schema.validation_enforcement"],
                evidence={"error_type": "SchemaValidationError"},
            )

        req_id = req["request_id"]
        op = req["operation"]
        params = req["parameters"]
        dec_id = self._generate_decision_id(req_id, op)

        matched_rules: List[str] = []

        # 1. Operation allowlist check
        if op not in self.allowed_operations:
            return PolicyDecision(
                decision_id=dec_id,
                status="DENIED",
                operation=op,
                reason=f"Operation '{op}' is not in policy allowed_operations",
                remediation=f"Request an allowed operation ({sorted(self.allowed_operations)}) or ask operator to update policy.",
                matched_rules=["access_control.allowed_operations"],
                evidence={"requested_operation": op},
            )
        matched_rules.append("access_control.allowed_operations")

        # 2. Check approval requirement
        # SECURITY INVARIANT: Real cryptographic approval verification is not yet implemented;
        # arbitrary token strings are NEVER accepted as verified.
        if op in self.require_approval_for:
            return PolicyDecision(
                decision_id=dec_id,
                status="DENIED",
                operation=op,
                reason=f"Operation '{op}' requires explicit operator approval, but approval-required operations are currently rejected fail-closed until trusted cryptographic signature verification is implemented.",
                remediation="Approval-required operations cannot be executed with unverified text tokens.",
                matched_rules=["access_control.approval_required_fail_closed"],
                evidence={"operation": op, "approval_configured": True},
            )

        # 3. Defensive checks per operation
        if op in ("read_text", "list_dir"):
            target_path = params.get("path", "")
            try:
                # Raw path checks before normalization (raw .. rejection, null bytes, sensitive names)
                components = validate_raw_path_string(target_path)
                self.path_validator.verify_subpath_policy(components)
                for comp in components:
                    if is_sensitive_name(comp):
                        raise PathValidationError(f"Access to sensitive component '{comp}' is denied")
            except PathValidationError as pve:
                return PolicyDecision(
                    decision_id=dec_id,
                    status="DENIED",
                    operation=op,
                    reason=f"Path boundary check failed: {pve}",
                    remediation="Provide a relative path within the authorized workspace root without directory traversal or sensitive names.",
                    matched_rules=["filesystem.boundary_confinement"],
                    evidence={"error_rule": "path_boundary_violation"},
                )

            matched_rules.append("filesystem.boundary_confinement")

            if op == "read_text":
                max_bytes_req = params.get("max_bytes", self.max_file_read_bytes)
                if max_bytes_req > self.max_file_read_bytes:
                    return PolicyDecision(
                        decision_id=dec_id,
                        status="DENIED",
                        operation=op,
                        reason=f"Requested read size ({max_bytes_req} bytes) exceeds policy max ({self.max_file_read_bytes} bytes)",
                        remediation=f"Limit read size to at most {self.max_file_read_bytes} bytes.",
                        matched_rules=["filesystem.size_quota"],
                        evidence={"requested_bytes": max_bytes_req, "allowed_max": self.max_file_read_bytes},
                    )
                matched_rules.append("filesystem.size_quota")

            display_subpath = "/".join(components) if components else "."
            return PolicyDecision(
                decision_id=dec_id,
                status="ALLOWED",
                operation=op,
                reason=f"Operation '{op}' validated within workspace boundary",
                remediation="None required; action is permitted.",
                matched_rules=matched_rules,
                evidence={
                    "sanitized_display_subpath": display_subpath,
                    "workspace_confinement": True,
                },
            )

        elif op == "run_python":
            timeout = params.get("timeout_seconds")
            policy_max_timeout = self.execution_rules.get("max_timeout_seconds", 30)

            if timeout is not None and timeout > policy_max_timeout:
                return PolicyDecision(
                    decision_id=dec_id,
                    status="DENIED",
                    operation=op,
                    reason=f"Execution timeout {timeout}s exceeds policy limit {policy_max_timeout}s",
                    remediation=f"Reduce timeout_seconds to <= {policy_max_timeout}s.",
                    matched_rules=["execution.timeout_bound"],
                    evidence={"requested_timeout": timeout, "policy_max_timeout": policy_max_timeout},
                )
            matched_rules.append("execution.timeout_bound")

            # Check script path containment if script_path was provided
            if "script_path" in params and params["script_path"]:
                try:
                    script_components = validate_raw_path_string(params["script_path"])
                    self.path_validator.verify_subpath_policy(script_components)
                    for comp in script_components:
                        if is_sensitive_name(comp):
                            raise PathValidationError(f"Access to sensitive component '{comp}' is denied")
                    display_target = "/".join(script_components)
                except PathValidationError as pve:
                    return PolicyDecision(
                        decision_id=dec_id,
                        status="DENIED",
                        operation=op,
                        reason=f"Python script path rejected: {pve}",
                        remediation="Point script_path to a valid Python file inside the authorized workspace.",
                        matched_rules=["filesystem.boundary_confinement"],
                        evidence={"error_rule": "script_path_violation"},
                    )
                matched_rules.append("filesystem.boundary_confinement")
            else:
                display_target = "inline_code_snippet"

            matched_rules.append("execution.network_isolation_strict")

            return PolicyDecision(
                decision_id=dec_id,
                status="ALLOWED",
                operation=op,
                reason="Python execution permitted under strict Bubblewrap namespace sandbox with read-only sanitized snapshot",
                remediation="None required; action is permitted for isolated execution.",
                matched_rules=matched_rules,
                evidence={
                    "script_target": display_target,
                    "timeout_seconds": timeout or policy_max_timeout,
                    "network_isolated": True,
                    "sandbox": "bubblewrap_linux",
                    "snapshot_mount": "read_only",
                },
            )

        return PolicyDecision(
            decision_id=dec_id,
            status="DENIED",
            operation=op,
            reason="Unrecognized operation encountered after schema check",
            remediation="Submit a supported operation.",
            matched_rules=["fallback.default_deny"],
            evidence={"operation": op},
        )
