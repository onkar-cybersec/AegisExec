"""
Tool Manifest Pinning and Integrity Drift Detection for AegisExec.

SECURITY NOTICE:
Baselines implement Trust-On-First-Use (TOFU), NOT cryptographically signed code
certificates. They detect tool descriptions and capability expansion between versions
as changes needing human operator review, NOT infallible prompt injection prevention.
Tools are NEVER executed while pinning or verifying manifests.
"""

from __future__ import annotations
import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple
from aegisexec.schemas import validate_tool_manifest, validate_json_string


def canonical_json_bytes(data: Any) -> bytes:
    """Produce deterministic UTF-8 bytes with alphabetically sorted keys."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def compute_manifest_hash(manifest_dict: Dict[str, Any]) -> Tuple[str, Dict[str, str]]:
    """
    Compute canonical SHA-256 for overall manifest and per-tool definitions.
    Volatile wrapper metadata is ignored; tool definitions are normalized.
    """
    tools = manifest_dict.get("tools", [])
    # Sort tools by name for stable comparison
    sorted_tools = sorted(tools, key=lambda t: t.get("name", ""))

    per_tool_hashes: Dict[str, str] = {}
    normalized_tool_list: List[Dict[str, Any]] = []

    for tool in sorted_tools:
        # Normalize tool item
        norm = {
            "name": tool["name"],
            "description": tool["description"],
            "operation": tool["operation"],
            "parameters_schema": tool.get("parameters_schema", {}),
            "risk_level": tool.get("risk_level", "medium"),
        }
        normalized_tool_list.append(norm)
        tool_bytes = canonical_json_bytes(norm)
        per_tool_hashes[tool["name"]] = hashlib.sha256(tool_bytes).hexdigest()

    manifest_payload = {
        "manifest_id": manifest_dict.get("manifest_id", "default"),
        "tools": normalized_tool_list,
    }
    manifest_bytes = canonical_json_bytes(manifest_payload)
    overall_hash = hashlib.sha256(manifest_bytes).hexdigest()

    return overall_hash, per_tool_hashes


class ManifestManager:
    """Manages baseline pinning and drift verification."""

    @staticmethod
    def pin(manifest_path_or_str: str) -> Dict[str, Any]:
        """
        Generate a baseline dict from a manifest file path or JSON string.
        Never executes any tool code.
        """
        if manifest_path_or_str.strip().startswith("{"):
            raw = manifest_path_or_str
        else:
            with open(manifest_path_or_str, "r", encoding="utf-8") as f:
                raw = f.read()

        data = validate_json_string(raw)
        validated = validate_tool_manifest(data)

        overall_hash, tool_hashes = compute_manifest_hash(validated)

        baseline = {
            "schema_version": "1.0",
            "baseline_type": "aegisexec_tool_baseline",
            "manifest_id": validated.get("manifest_id"),
            "canonical_sha256": overall_hash,
            "tool_count": len(validated.get("tools", [])),
            "tool_hashes": tool_hashes,
            "tools_snapshot": sorted(validated.get("tools", []), key=lambda t: t["name"]),
        }
        return baseline

    @staticmethod
    def verify(manifest_raw: str | Dict[str, Any], baseline_raw: str | Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify tool manifest against baseline. Returns drift report and human-readable diff.
        """
        if isinstance(manifest_raw, str):
            if manifest_raw.strip().startswith("{"):
                m_dict = validate_json_string(manifest_raw)
            else:
                with open(manifest_raw, "r", encoding="utf-8") as f:
                    m_dict = validate_json_string(f.read())
        else:
            m_dict = manifest_raw

        if isinstance(baseline_raw, str):
            if baseline_raw.strip().startswith("{"):
                b_dict = validate_json_string(baseline_raw)
            else:
                with open(baseline_raw, "r", encoding="utf-8") as f:
                    b_dict = validate_json_string(f.read())
        else:
            b_dict = baseline_raw

        validated_manifest = validate_tool_manifest(m_dict)
        current_hash, current_tool_hashes = compute_manifest_hash(validated_manifest)
        baseline_hash = b_dict.get("canonical_sha256", "")
        baseline_tool_hashes = b_dict.get("tool_hashes", {})
        baseline_tools_snapshot = {t["name"]: t for t in b_dict.get("tools_snapshot", [])}

        current_tools = {t["name"]: t for t in validated_manifest.get("tools", [])}

        changes: List[Dict[str, Any]] = []
        added_tools: List[str] = []
        removed_tools: List[str] = []
        modified_tools: List[str] = []

        # Check for added or modified tools
        for name, tool in current_tools.items():
            if name not in baseline_tool_hashes:
                added_tools.append(name)
                changes.append({
                    "tool": name,
                    "type": "ADDED_TOOL",
                    "details": f"New tool '{name}' introduced into manifest (operation: {tool['operation']})"
                })
            elif current_tool_hashes[name] != baseline_tool_hashes[name]:
                modified_tools.append(name)
                base_tool = baseline_tools_snapshot.get(name, {})
                diffs = []
                if tool.get("description") != base_tool.get("description"):
                    diffs.append(f"Description changed from '{base_tool.get('description')}' to '{tool.get('description')}'")
                if tool.get("operation") != base_tool.get("operation"):
                    diffs.append(f"Operation changed from '{base_tool.get('operation')}' to '{tool.get('operation')}'")
                if tool.get("risk_level") != base_tool.get("risk_level"):
                    diffs.append(f"Risk level changed from '{base_tool.get('risk_level')}' to '{tool.get('risk_level')}'")
                if tool.get("parameters_schema") != base_tool.get("parameters_schema"):
                    diffs.append("Parameters schema expanded or altered")

                changes.append({
                    "tool": name,
                    "type": "MODIFIED_TOOL",
                    "details": "; ".join(diffs) if diffs else "Normalized definition hash mismatch"
                })

        # Check for removed tools
        for name in baseline_tool_hashes:
            if name not in current_tools:
                removed_tools.append(name)
                changes.append({
                    "tool": name,
                    "type": "REMOVED_TOOL",
                    "details": f"Tool '{name}' removed from current manifest"
                })

        has_drift = bool(changes or current_hash != baseline_hash)

        return {
            "status": "DRIFT_DETECTED" if has_drift else "VERIFIED_MATCH",
            "matches_baseline": not has_drift,
            "manifest_hash": current_hash,
            "baseline_hash": baseline_hash,
            "changes_count": len(changes),
            "added_tools": added_tools,
            "removed_tools": removed_tools,
            "modified_tools": modified_tools,
            "changes": changes,
            "limitations_notice": (
                "TOFU manifest pinning detects structural and descriptive drift between revisions. "
                "It does not guarantee runtime code safety and is not a substitute for behavioral sandboxing."
            ),
        }
