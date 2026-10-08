"""
Audit Report Generator for AegisExec.
Generates structured JSON or self-contained HTML reports from audit.jsonl.
Strictly bounds total bytes read, record counts, and HTML-escapes all dynamic fields.
"""

from __future__ import annotations
import html
import json
import os
from collections import Counter
from typing import Any, Dict, List

MAX_AUDIT_REPORT_BYTES = 10 * 1024 * 1024  # 10 MB maximum
MAX_AUDIT_RECORDS = 10_000
MAX_LINE_BYTES = 16384


def parse_audit_log(jsonl_path: str) -> List[Dict[str, Any]]:
    """Parse JSONL audit entries with strict file and record size bounds."""
    if not os.path.exists(jsonl_path):
        return []

    entries: List[Dict[str, Any]] = []
    total_bytes_read = 0

    with open(jsonl_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            total_bytes_read += len(line.encode("utf-8"))
            if total_bytes_read > MAX_AUDIT_REPORT_BYTES:
                break
            if len(line) > MAX_LINE_BYTES:
                continue

            line_str = line.strip()
            if not line_str:
                continue

            try:
                item = json.loads(line_str)
                if isinstance(item, dict):
                    entries.append(item)
            except json.JSONDecodeError:
                continue

            if len(entries) >= MAX_AUDIT_RECORDS:
                break

    return entries


def compute_metrics(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute aggregate security and operational metrics."""
    total_events = len(entries)
    allowed = sum(1 for e in entries if e.get("status") in ("ALLOWED", "EXECUTED"))
    denied = sum(1 for e in entries if e.get("status") in ("DENIED", "EXECUTION_FAILED"))

    operations = Counter(str(e.get("operation", "unknown")) for e in entries)
    violations = Counter()

    for e in entries:
        if e.get("status") in ("DENIED", "EXECUTION_FAILED"):
            for rule in e.get("matched_rules", []):
                violations[str(rule)] += 1

    return {
        "total_events": total_events,
        "allowed_count": allowed,
        "denied_count": denied,
        "allow_rate_pct": round((allowed / total_events * 100), 1) if total_events > 0 else 0.0,
        "operations_breakdown": dict(operations),
        "violations_breakdown": dict(violations),
        "entries": entries,
    }


def generate_json_report(jsonl_path: str) -> str:
    """Generate structured JSON report."""
    entries = parse_audit_log(jsonl_path)
    metrics = compute_metrics(entries)
    metrics["audit_file"] = jsonl_path
    metrics["report_type"] = "aegisexec_audit_summary_v1"
    metrics["limitations_notice"] = [
        "AegisExec only mediates actions routed through its broker interface.",
        "Path checks do not isolate executing code; Linux Bubblewrap namespaces are required.",
        "Tool baselines are TOFU hashes, not code signing or infallible prompt injection defenses.",
    ]
    return json.dumps(metrics, indent=2)


def generate_html_report(jsonl_path: str) -> str:
    """Generate self-contained HTML audit report with full HTML escaping."""
    entries = parse_audit_log(jsonl_path)
    metrics = compute_metrics(entries)

    total = metrics["total_events"]
    allowed = metrics["allowed_count"]
    denied = metrics["denied_count"]
    rate = metrics["allow_rate_pct"]

    # Table rows (most recent 50)
    rows_html = []
    for e in entries[-50:]:
        ts = html.escape(str(e.get("timestamp", ""))[:32])
        ev_id = html.escape(str(e.get("event_id", ""))[:32])
        op = html.escape(str(e.get("operation", ""))[:32])
        st = html.escape(str(e.get("status", ""))[:32])
        reason_code = html.escape(str(e.get("reason_code", ""))[:80])
        rules = html.escape(", ".join(str(r) for r in e.get("matched_rules", []))[:120])

        status_class = "status-allow" if st in ("ALLOWED", "EXECUTED") else "status-deny"
        rows_html.append(f"""
        <tr>
          <td><code>{ts}</code></td>
          <td><code>{ev_id}</code></td>
          <td><b>{op}</b></td>
          <td><span class="badge {status_class}">{st}</span></td>
          <td>{reason_code}</td>
          <td><small>{rules}</small></td>
        </tr>
        """)

    table_body = "\n".join(rows_html) if rows_html else "<tr><td colspan='6'>No audit records logged yet.</td></tr>"

    violations_items = []
    for k, v in metrics["violations_breakdown"].items():
        violations_items.append(f"<li><code>{html.escape(k)}</code>: <b>{v}</b> block(s)</li>")
    violations_html = "\n".join(violations_items) if violations_items else "<li>No policy violations recorded</li>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>AegisExec Audit Security Report</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: #0d1117;
      color: #c9d1d9;
      margin: 0;
      padding: 24px;
      line-height: 1.5;
    }}
    .container {{ max-width: 1100px; margin: 0 auto; }}
    h1, h2, h3 {{ color: #58a6ff; font-weight: 600; }}
    .header {{ border-bottom: 1px solid #30363d; padding-bottom: 16px; margin-bottom: 24px; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }}
    .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; }}
    .card .num {{ font-size: 28px; font-weight: bold; }}
    .card .num.green {{ color: #3fb950; }}
    .card .num.red {{ color: #f85149; }}
    .card .num.blue {{ color: #58a6ff; }}
    .card .label {{ color: #8b949e; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 16px; background: #161b22; border-radius: 6px; overflow: hidden; }}
    th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid #21262d; font-size: 13px; }}
    th {{ background: #21262d; color: #f0f6fc; font-weight: 600; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }}
    .status-allow {{ background: rgba(63, 185, 80, 0.2); color: #3fb950; border: 1px solid #3fb950; }}
    .status-deny {{ background: rgba(248, 81, 73, 0.2); color: #f85149; border: 1px solid #f85149; }}
    .notice {{ background: #1c2128; border-left: 4px solid #d29922; padding: 14px; margin-top: 24px; border-radius: 4px; font-size: 13px; }}
    code {{ font-family: monospace; color: #79c0ff; background: rgba(110, 118, 129, 0.2); padding: 2px 4px; border-radius: 3px; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>AegisExec Defensive Audit Report</h1>
      <p>Audit Log Source: <code>{html.escape(jsonl_path)}</code> | Author: Built by onkar-cybersec</p>
    </div>

    <div class="cards">
      <div class="card">
        <div class="label">Total Evaluated Actions</div>
        <div class="num blue">{total}</div>
      </div>
      <div class="card">
        <div class="label">Allowed Operations</div>
        <div class="num green">{allowed}</div>
      </div>
      <div class="card">
        <div class="label">Blocked Violations</div>
        <div class="num red">{denied}</div>
      </div>
      <div class="card">
        <div class="label">Compliance Allow Rate</div>
        <div class="num blue">{rate}%</div>
      </div>
    </div>

    <div class="card" style="margin-bottom: 24px;">
      <h3>Violations Breakdown</h3>
      <ul>
        {violations_html}
      </ul>
    </div>

    <h3>Recent Action Events (Bounded View)</h3>
    <table>
      <thead>
        <tr>
          <th>Timestamp (UTC)</th>
          <th>Event ID</th>
          <th>Operation</th>
          <th>Status</th>
          <th>Reason Code</th>
          <th>Rules</th>
        </tr>
      </thead>
      <tbody>
        {table_body}
      </tbody>
    </table>

    <div class="notice">
      <b>Security Boundaries and Limitations:</b>
      <ul>
        <li>AegisExec operates as a mediation gateway. If an agent executes directly on the host bypassing AegisExec, this broker cannot enforce constraints.</li>
        <li>Filesystem path resolution defends against traversal, but application-level checks face TOCTOU limitations; isolation of code relies strictly on Bubblewrap namespaces.</li>
        <li>Tool baselines implement Trust-On-First-Use (TOFU) hashing to catch modification and capability expansion, not code signing or infallible prompt injection detection.</li>
      </ul>
    </div>
  </div>
</body>
</html>"""
