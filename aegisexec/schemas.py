"""
Versioned JSON Schemas and Strict Validation for AegisExec.
Defends against oversized payloads, duplicate JSON keys, type confusion,
bool-as-int coercion, NaN/Infinity, and unknown fields.
Fail-closed default.
"""

from __future__ import annotations
import json
import math
from typing import Any, Dict, List, Tuple

MAX_JSON_BYTES = 1 * 1024 * 1024  # 1 MB maximum payload size
MAX_STRING_LEN = 100_000
MAX_CODE_LEN = 500_000
MAX_ARGS_COUNT = 100
MAX_ARG_LEN = 4096

# Hard upper bounds on policy constraints
POLICY_HARD_MAX_TIMEOUT_SECONDS = 300.0  # 5 minutes maximum
POLICY_HARD_MAX_OUTPUT_BYTES = 10 * 1024 * 1024  # 10 MB maximum
POLICY_HARD_MAX_MEMORY_MB = 4096  # 4 GB maximum
POLICY_HARD_MAX_READ_BYTES = 50 * 1024 * 1024  # 50 MB maximum

SUPPORTED_OPERATIONS = frozenset({"read_text", "list_dir", "run_python"})
VALID_SCHEMA_VERSIONS = frozenset({"1.0"})


class SchemaValidationError(Exception):
    """Raised when JSON schema validation fails."""
    pass


def is_exact_int(val: Any) -> bool:
    """Return True if val is an int and NOT a bool."""
    return isinstance(val, int) and not isinstance(val, bool)


def is_exact_number(val: Any) -> bool:
    """Return True if val is a finite int or float and NOT a bool."""
    if isinstance(val, bool):
        return False
    if not isinstance(val, (int, float)):
        return False
    try:
        return math.isfinite(val)
    except OverflowError:
        return False


def _strict_pairs_hook(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    """Detect duplicate keys during JSON decoding."""
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SchemaValidationError(f"Duplicate JSON key detected: '{key}'")
        result[key] = value
    return result


def validate_json_string(raw_json: str, max_bytes: int = MAX_JSON_BYTES) -> Dict[str, Any]:
    """Parse JSON with strict byte bounds, duplicate key detection, and type checks."""
    if not isinstance(raw_json, str):
        raise SchemaValidationError("Expected string input for JSON parsing")

    encoded_len = len(raw_json.encode("utf-8"))
    if encoded_len > max_bytes:
        raise SchemaValidationError(
            f"Payload size {encoded_len} bytes exceeds maximum allowed {max_bytes} bytes"
        )
    try:
        data = json.loads(raw_json, object_pairs_hook=_strict_pairs_hook)
    except SchemaValidationError:
        raise
    except Exception as exc:
        raise SchemaValidationError(f"Invalid JSON format: {exc}") from exc

    if not isinstance(data, dict):
        raise SchemaValidationError("Root JSON object must be an associative mapping (dict)")
    return data


def _check_allowed_keys(data: Dict[str, Any], allowed_keys: set[str], location: str) -> None:
    if not isinstance(data, dict):
        raise SchemaValidationError(f"Expected dict at {location}, got {type(data).__name__}")
    unknown = set(data.keys()) - allowed_keys
    if unknown:
        raise SchemaValidationError(f"Unknown unexpected fields in {location}: {sorted(unknown)}")


def validate_action_request(data: Any) -> Dict[str, Any]:
    """
    Validate ActionRequest JSON schema v1.0.
    Rejects non-dict root, unknown fields, oversized strings, bool-coercion, and type confusion.
    """
    if not isinstance(data, dict):
        raise SchemaValidationError(f"ActionRequest root must be a dict, got {type(data).__name__}")
    try:
        if len(json.dumps(data, allow_nan=False).encode('utf-8')) > MAX_JSON_BYTES:
            raise SchemaValidationError('ActionRequest exceeds byte budget')
    except (ValueError, TypeError, RecursionError):
        raise SchemaValidationError('ActionRequest contains invalid JSON values') from None

    allowed_top_keys = {
        "schema_version",
        "request_id",
        "operation",
        "parameters",
        "context",
        "approval",
    }
    _check_allowed_keys(data, allowed_top_keys, "ActionRequest")

    # Required fields
    for field in ("schema_version", "request_id", "operation", "parameters"):
        if field not in data:
            raise SchemaValidationError(f"Missing required field in ActionRequest: '{field}'")

    if not isinstance(data["schema_version"], str):
        raise SchemaValidationError(f"Field 'schema_version' must be string, got {type(data['schema_version']).__name__}")

    if data["schema_version"] not in VALID_SCHEMA_VERSIONS:
        raise SchemaValidationError(
            f"Unsupported schema_version '{data['schema_version']}'. Expected one of {sorted(VALID_SCHEMA_VERSIONS)}"
        )

    if not isinstance(data["request_id"], str) or not data["request_id"].strip():
        raise SchemaValidationError("Field 'request_id' must be a non-empty string")
    if len(data["request_id"]) > 256:
        raise SchemaValidationError("Field 'request_id' exceeds maximum length of 256 characters")

    if not isinstance(data["operation"], str):
        raise SchemaValidationError(f"Field 'operation' must be string, got {type(data['operation']).__name__}")

    if data["operation"] not in SUPPORTED_OPERATIONS:
        raise SchemaValidationError(
            f"Unsupported operation '{data['operation']}'. Supported: {sorted(SUPPORTED_OPERATIONS)}"
        )

    if not isinstance(data["parameters"], dict):
        raise SchemaValidationError(f"Field 'parameters' must be a dict, got {type(data['parameters']).__name__}")

    op = data["operation"]
    params = data["parameters"]

    if op == "read_text":
        _check_allowed_keys(params, {"path", "max_bytes"}, "read_text parameters")
        if "path" not in params or not isinstance(params["path"], str) or not params["path"].strip():
            raise SchemaValidationError("read_text requires a non-empty string 'path'")
        if len(params["path"]) > MAX_STRING_LEN:
            raise SchemaValidationError("Path parameter exceeds maximum allowed length")
        if "max_bytes" in params:
            if not is_exact_int(params["max_bytes"]) or params["max_bytes"] <= 0:
                raise SchemaValidationError("read_text 'max_bytes' must be a positive integer (not boolean or float)")
            if params["max_bytes"] > POLICY_HARD_MAX_READ_BYTES:
                raise SchemaValidationError(f"read_text 'max_bytes' exceeds hard maximum {POLICY_HARD_MAX_READ_BYTES}")

    elif op == "list_dir":
        _check_allowed_keys(params, {"path", "max_depth", "include_hidden"}, "list_dir parameters")
        if "path" not in params or not isinstance(params["path"], str) or not params["path"].strip():
            raise SchemaValidationError("list_dir requires a non-empty string 'path'")
        if len(params["path"]) > MAX_STRING_LEN:
            raise SchemaValidationError("Path parameter exceeds maximum allowed length")
        if "max_depth" in params:
            if not is_exact_int(params["max_depth"]) or params["max_depth"] < 0 or params["max_depth"] > 20:
                raise SchemaValidationError("list_dir 'max_depth' must be an integer between 0 and 20")
        if "include_hidden" in params and not isinstance(params["include_hidden"], bool):
            raise SchemaValidationError("list_dir 'include_hidden' must be a boolean")

    elif op == "run_python":
        _check_allowed_keys(params, {"code", "script_path", "timeout_seconds", "args"}, "run_python parameters")
        has_code = "code" in params and isinstance(params["code"], str) and bool(params["code"].strip())
        has_script = "script_path" in params and isinstance(params["script_path"], str) and bool(params["script_path"].strip())

        if not (has_code or has_script):
            raise SchemaValidationError("run_python requires either non-empty string 'code' or 'script_path'")
        if has_code and has_script:
            raise SchemaValidationError("run_python cannot specify both 'code' and 'script_path'")

        if has_code and len(params["code"]) > MAX_CODE_LEN:
            raise SchemaValidationError(f"Code string length exceeds maximum {MAX_CODE_LEN}")
        if has_script and len(params["script_path"]) > MAX_STRING_LEN:
            raise SchemaValidationError("script_path exceeds maximum allowed length")

        if "timeout_seconds" in params:
            t = params["timeout_seconds"]
            if not is_exact_number(t) or t <= 0:
                raise SchemaValidationError("run_python 'timeout_seconds' must be a finite positive number (not bool)")
            if t > POLICY_HARD_MAX_TIMEOUT_SECONDS:
                raise SchemaValidationError(f"run_python 'timeout_seconds' exceeds hard maximum of {POLICY_HARD_MAX_TIMEOUT_SECONDS}s")

        if "args" in params:
            if not isinstance(params["args"], list):
                raise SchemaValidationError("run_python 'args' must be a list of strings")
            if len(params["args"]) > MAX_ARGS_COUNT:
                raise SchemaValidationError(f"run_python 'args' count exceeds maximum {MAX_ARGS_COUNT}")
            for a in params["args"]:
                if not isinstance(a, str) or len(a) > MAX_ARG_LEN:
                    raise SchemaValidationError(f"Argument item must be string <= {MAX_ARG_LEN} chars")

    # Validate optional context
    if "context" in data:
        if not isinstance(data["context"], dict):
            raise SchemaValidationError("Field 'context' must be a dict")
        _check_allowed_keys(data["context"], {"agent_id", "task_id", "session_id", "metadata"}, "context")
        for ck, cv in data["context"].items():
            if not isinstance(cv, (str, dict, int, bool)) or (isinstance(cv, str) and len(cv) > 1024):
                raise SchemaValidationError(f"Invalid context value for key '{ck}'")

    # Validate optional approval
    if "approval" in data:
        if not isinstance(data["approval"], dict):
            raise SchemaValidationError("Field 'approval' must be a dict")
        _check_allowed_keys(data["approval"], {"approved_by", "token", "timestamp", "reason"}, "approval")
        if "approved_by" not in data["approval"] or not isinstance(data["approval"]["approved_by"], str):
            raise SchemaValidationError("approval requires string 'approved_by'")
        if "token" not in data["approval"] or not isinstance(data["approval"]["token"], str):
            raise SchemaValidationError("approval requires string 'token'")

    return data


def validate_policy(data: Any) -> Dict[str, Any]:
    """
    Validate Policy JSON schema v1.0.
    Enforces hard bounds on timeouts, memory, output size, and read bounds.
    """
    if not isinstance(data, dict):
        raise SchemaValidationError(f"Policy root must be a dict, got {type(data).__name__}")

    allowed_top_keys = {
        "schema_version",
        "policy_id",
        "name",
        "description",
        "workspace_root",
        "allowed_operations",
        "path_rules",
        "execution_rules",
        "require_approval_for",
        "audit",
    }
    _check_allowed_keys(data, allowed_top_keys, "Policy")

    for req in ("schema_version", "policy_id", "name", "workspace_root", "allowed_operations"):
        if req not in data:
            raise SchemaValidationError(f"Missing required field in Policy: '{req}'")

    if not isinstance(data["schema_version"], str) or data["schema_version"] not in VALID_SCHEMA_VERSIONS:
        raise SchemaValidationError(f"Unsupported policy schema_version '{data.get('schema_version')}'")

    if not isinstance(data["policy_id"], str) or not data["policy_id"].strip():
        raise SchemaValidationError("Policy 'policy_id' must be a non-empty string")

    if not isinstance(data["workspace_root"], str) or not data["workspace_root"].strip():
        raise SchemaValidationError("Policy 'workspace_root' must be a non-empty string path")

    if not isinstance(data["allowed_operations"], list):
        raise SchemaValidationError("Policy 'allowed_operations' must be a list of strings")

    for op in data["allowed_operations"]:
        if not isinstance(op, str) or op not in SUPPORTED_OPERATIONS:
            raise SchemaValidationError(f"Policy contains invalid operation '{op}'. Supported: {sorted(SUPPORTED_OPERATIONS)}")

    # path_rules
    if "path_rules" in data:
        if not isinstance(data["path_rules"], dict):
            raise SchemaValidationError("Policy 'path_rules' must be a dict")
        _check_allowed_keys(data["path_rules"], {"allowed_subpaths", "denied_patterns", "max_file_read_bytes"}, "path_rules")
        if "allowed_subpaths" in data["path_rules"]:
            if not isinstance(data["path_rules"]["allowed_subpaths"], list) or not all(isinstance(x, str) for x in data["path_rules"]["allowed_subpaths"]):
                raise SchemaValidationError("path_rules.allowed_subpaths must be a list of strings")
        if "denied_patterns" in data["path_rules"]:
            if not isinstance(data["path_rules"]["denied_patterns"], list) or not all(isinstance(x, str) for x in data["path_rules"]["denied_patterns"]):
                raise SchemaValidationError("path_rules.denied_patterns must be a list of strings")
        if "max_file_read_bytes" in data["path_rules"]:
            m = data["path_rules"]["max_file_read_bytes"]
            if not is_exact_int(m) or m <= 0:
                raise SchemaValidationError("path_rules.max_file_read_bytes must be a positive integer")
            if m > POLICY_HARD_MAX_READ_BYTES:
                raise SchemaValidationError(f"path_rules.max_file_read_bytes exceeds hard limit {POLICY_HARD_MAX_READ_BYTES}")

    # execution_rules
    if "execution_rules" in data:
        if not isinstance(data["execution_rules"], dict):
            raise SchemaValidationError("Policy 'execution_rules' must be a dict")
        _check_allowed_keys(data["execution_rules"], {
            "max_timeout_seconds",
            "max_output_bytes",
            "max_memory_mb",
            "allow_network",
            "allowed_domains",
        }, "execution_rules")

        if "max_timeout_seconds" in data["execution_rules"]:
            t = data["execution_rules"]["max_timeout_seconds"]
            if not is_exact_number(t) or t <= 0:
                raise SchemaValidationError("execution_rules.max_timeout_seconds must be a finite positive number")
            if t > POLICY_HARD_MAX_TIMEOUT_SECONDS:
                raise SchemaValidationError(f"execution_rules.max_timeout_seconds exceeds hard limit {POLICY_HARD_MAX_TIMEOUT_SECONDS}s")

        if "max_output_bytes" in data["execution_rules"]:
            o = data["execution_rules"]["max_output_bytes"]
            if not is_exact_int(o) or o <= 0:
                raise SchemaValidationError("execution_rules.max_output_bytes must be a positive integer")
            if o > POLICY_HARD_MAX_OUTPUT_BYTES:
                raise SchemaValidationError(f"execution_rules.max_output_bytes exceeds hard limit {POLICY_HARD_MAX_OUTPUT_BYTES}")

        if "max_memory_mb" in data["execution_rules"]:
            m = data["execution_rules"]["max_memory_mb"]
            if not is_exact_int(m) or m <= 0:
                raise SchemaValidationError("execution_rules.max_memory_mb must be a positive integer")
            if m > POLICY_HARD_MAX_MEMORY_MB:
                raise SchemaValidationError(f"execution_rules.max_memory_mb exceeds hard limit {POLICY_HARD_MAX_MEMORY_MB} MB")

        if "allow_network" in data["execution_rules"]:
            if data["execution_rules"]["allow_network"] is not False:
                raise SchemaValidationError(
                    "Hard defense rule: 'allow_network' must be false. Raw outbound network egress is strictly forbidden in v1 sandbox."
                )

    if "require_approval_for" in data:
        if not isinstance(data["require_approval_for"], list) or not all(isinstance(x, str) for x in data["require_approval_for"]):
            raise SchemaValidationError("Policy 'require_approval_for' must be a list of strings")

    if "audit" in data:
        if not isinstance(data["audit"], dict):
            raise SchemaValidationError("Policy 'audit' must be a dict")
        _check_allowed_keys(data["audit"], {"enabled", "log_path"}, "audit")
        if "enabled" in data["audit"] and not isinstance(data["audit"]["enabled"], bool):
            raise SchemaValidationError("audit.enabled must be a boolean")
        if "log_path" in data["audit"] and not isinstance(data["audit"]["log_path"], str):
            raise SchemaValidationError("audit.log_path must be a string")

    return data


def validate_tool_manifest(data: Any) -> Dict[str, Any]:
    """Validate ToolManifest JSON schema v1.0."""
    if not isinstance(data, dict):
        raise SchemaValidationError(f"ToolManifest root must be a dict, got {type(data).__name__}")

    allowed_top_keys = {"schema_version", "manifest_id", "tools", "metadata"}
    _check_allowed_keys(data, allowed_top_keys, "ToolManifest")

    for req in ("schema_version", "manifest_id", "tools"):
        if req not in data:
            raise SchemaValidationError(f"Missing required field in ToolManifest: '{req}'")

    if not isinstance(data["schema_version"], str) or data["schema_version"] not in VALID_SCHEMA_VERSIONS:
        raise SchemaValidationError(f"Unsupported tool manifest schema_version '{data.get('schema_version')}'")

    if not isinstance(data["manifest_id"], str) or not data["manifest_id"].strip():
        raise SchemaValidationError("manifest_id must be a non-empty string")

    if not isinstance(data["tools"], list):
        raise SchemaValidationError("ToolManifest 'tools' must be a list of tool objects")

    tool_names = set()
    for tool in data["tools"]:
        if not isinstance(tool, dict):
            raise SchemaValidationError("Each item in 'tools' must be a dict")
        _check_allowed_keys(tool, {"name", "description", "operation", "parameters_schema", "risk_level"}, "tool")

        for req in ("name", "description", "operation"):
            if req not in tool or not isinstance(tool[req], str) or not tool[req].strip():
                raise SchemaValidationError(f"Tool requires non-empty string '{req}'")

        if tool["name"] in tool_names:
            raise SchemaValidationError(f"Duplicate tool name in manifest: '{tool['name']}'")
        tool_names.add(tool["name"])

        if tool["operation"] not in SUPPORTED_OPERATIONS:
            raise SchemaValidationError(f"Tool '{tool['name']}' references unsupported operation '{tool['operation']}'")

        if "risk_level" in tool:
            if tool["risk_level"] not in {"low", "medium", "high"}:
                raise SchemaValidationError("Tool 'risk_level' must be 'low', 'medium', or 'high'")

    return data
