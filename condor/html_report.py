"""HTML report renderer for Condor scan results."""
from __future__ import annotations

import html

from .compliance import get_compliance_refs
from .core.models import ScanResult, Severity

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

_SEV_COLORS = {
    "critical": "#c0392b",
    "high":     "#e74c3c",
    "medium":   "#e67e22",
    "low":      "#3498db",
    "info":     "#7f8c8d",
}

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f6fa; color: #2c3e50; padding: 2rem; }
.header { background: #1a1a2e; color: #fff; border-radius: 8px; padding: 1.5rem 2rem; margin-bottom: 1.5rem; }
.header h1 { font-size: 1.6rem; margin-bottom: 0.4rem; }
.header .meta { font-size: 0.85rem; color: #bdc3c7; line-height: 1.8; }
.summary { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; }
.badge { border-radius: 6px; padding: 0.6rem 1.2rem; color: #fff; font-weight: 700; font-size: 0.9rem; display: flex; flex-direction: column; align-items: center; min-width: 90px; }
.badge .count { font-size: 1.8rem; line-height: 1; }
.badge .label { font-size: 0.7rem; opacity: 0.9; margin-top: 2px; }
.no-findings { background: #d5f5e3; border: 1px solid #27ae60; border-radius: 8px; padding: 1.5rem 2rem; color: #1e8449; font-weight: 600; font-size: 1rem; }
.findings-table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }
.findings-table thead th { background: #2c3e50; color: #fff; padding: 0.75rem 1rem; text-align: left; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }
.findings-table tbody tr:nth-child(even) { background: #fafbfc; }
.findings-table tbody tr:hover { background: #eaf4fd; }
details summary { cursor: pointer; list-style: none; }
details summary::-webkit-details-marker { display: none; }
.sev-badge { display: inline-block; border-radius: 4px; padding: 2px 8px; color: #fff; font-size: 0.72rem; font-weight: 700; letter-spacing: 0.04em; }
.cwe-badge { display: inline-block; border-radius: 4px; padding: 1px 6px; background: #6c3483; color: #fff; font-size: 0.68rem; font-family: monospace; font-weight: 700; margin-left: 6px; vertical-align: middle; }
td { padding: 0.65rem 1rem; font-size: 0.88rem; vertical-align: top; }
.detail-box { margin-top: 0.6rem; padding: 0.75rem; background: #f8f9fa; border-radius: 4px; border-left: 3px solid #bdc3c7; }
.detail-box h4 { font-size: 0.75rem; text-transform: uppercase; color: #7f8c8d; margin-bottom: 0.3rem; letter-spacing: 0.05em; }
.detail-box p { font-size: 0.85rem; line-height: 1.5; }
.detail-box pre { font-size: 0.78rem; white-space: pre-wrap; word-break: break-all; background: #ecf0f1; padding: 0.5rem; border-radius: 3px; margin-top: 0.3rem; max-height: 200px; overflow-y: auto; }
.compliance-grid { display: flex; flex-wrap: wrap; gap: 0.4rem; margin-top: 0.4rem; }
.compliance-tag { display: inline-block; border-radius: 3px; padding: 2px 6px; font-size: 0.7rem; font-weight: 600; color: #fff; }
.confidence { color: #7f8c8d; font-size: 0.8rem; }
.endpoint { font-family: monospace; font-size: 0.78rem; color: #5d6d7e; }
@media (prefers-color-scheme: dark) {
  body { background: #1a1a2e; color: #ecf0f1; }
  .findings-table { background: #16213e; box-shadow: 0 1px 4px rgba(0,0,0,0.4); }
  .findings-table tbody tr:nth-child(even) { background: #0f3460; }
  .findings-table tbody tr:hover { background: #1a4a7a; }
  .detail-box { background: #0f3460; border-left-color: #4a6fa5; }
  .detail-box pre { background: #0a2540; }
  .no-findings { background: #1e4d2b; border-color: #27ae60; color: #58d68d; }
}
:root[data-theme="dark"] body { background: #1a1a2e; color: #ecf0f1; }
:root[data-theme="light"] body { background: #f5f6fa; color: #2c3e50; }
"""


def _e(text: str) -> str:
    return html.escape(str(text), quote=True)


def _compliance_html(owasp_id: str) -> str:
    refs = get_compliance_refs(owasp_id)
    if not refs:
        return ""
    parts = []
    color_map = {"iso_42001": "#1a5276", "nist_ai_rmf": "#1e8449", "eu_ai_act": "#784212"}
    label_map = {"iso_42001": "ISO 42001", "nist_ai_rmf": "NIST AI RMF", "eu_ai_act": "EU AI Act"}
    for key in ("iso_42001", "nist_ai_rmf", "eu_ai_act"):
        items = refs.get(key, [])
        color = color_map[key]
        label = label_map[key]
        for item in items:
            parts.append(
                f'<span class="compliance-tag" style="background:{color}" title="{_e(label)}">'
                f"{_e(item)}</span>"
            )
    return (
        '<div class="detail-box">'
        '<h4>Compliance Mapping</h4>'
        f'<div class="compliance-grid">{"".join(parts)}</div>'
        '</div>'
    )


def to_html(result: ScanResult, version: str) -> str:
    sorted_findings = sorted(
        result.findings,
        key=lambda f: _SEV_ORDER.index(f.severity) if f.severity in _SEV_ORDER else 99,
    )

    counts = result.finding_count
    summary_badges = ""
    for sev in _SEV_ORDER:
        n = counts.get(sev.value, 0)
        if n:
            color = _SEV_COLORS.get(sev.value, "#7f8c8d")
            summary_badges += (
                f'<div class="badge" style="background:{color}">'
                f'<span class="count">{n}</span>'
                f'<span class="label">{sev.value.upper()}</span>'
                f'</div>'
            )

    if result.started_at:
        date_str = result.started_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    else:
        date_str = "—"

    if result.duration_seconds is not None:
        dur_str = f"{result.duration_seconds:.1f}s"
    else:
        dur_str = "—"

    meta_lines = [
        f"Target: {_e(result.target)}",
        f"Platform: {_e(result.platform)}",
        f"Date: {date_str}",
        f"Duration: {dur_str}",
        f"Modules: {', '.join(_e(m) for m in result.modules_run) or '—'}",
        f"Condor v{_e(version)}",
    ]
    meta_html = " &nbsp;·&nbsp; ".join(meta_lines)

    if not sorted_findings:
        body_html = '<div class="no-findings">✅ No findings detected — target appears clean for the modules run.</div>'
    else:
        rows = ""
        for f in sorted_findings:
            color = _SEV_COLORS.get(f.severity.value, "#7f8c8d")
            sev_badge = f'<span class="sev-badge" style="background:{color}">{_e(f.severity.value.upper())}</span>'
            cwe_badge = (
                f'<span class="cwe-badge">{_e(f.cwe_id)}</span>'
                if f.cwe_id else ""
            )
            detail_parts = ""
            if f.description:
                detail_parts += (
                    f'<div class="detail-box">'
                    f'<h4>Description</h4><p>{_e(f.description)}</p>'
                    f'</div>'
                )
            if f.evidence:
                detail_parts += (
                    f'<div class="detail-box">'
                    f'<h4>Evidence</h4><pre>{_e(f.evidence)}</pre>'
                    f'</div>'
                )
            if f.remediation:
                detail_parts += (
                    f'<div class="detail-box">'
                    f'<h4>Remediation</h4><pre>{_e(f.remediation)}</pre>'
                    f'</div>'
                )
            detail_parts += _compliance_html(f.owasp_id.value)
            rows += (
                f"<tr><td>{sev_badge}</td>"
                f"<td><details><summary>{_e(f.title)}{cwe_badge}</summary>{detail_parts}</details></td>"
                f"<td>{_e(f.owasp_id.value)}</td>"
                f'<td class="endpoint">{_e(f.endpoint) if f.endpoint else "—"}</td>'
                f'<td class="confidence">{f.confidence}%</td>'
                f"</tr>\n"
            )
        body_html = (
            '<table class="findings-table">'
            "<thead><tr>"
            "<th>Severity</th><th>Finding</th><th>OWASP</th><th>Endpoint</th><th>Confidence</th>"
            "</tr></thead>"
            f"<tbody>{rows}</tbody>"
            "</table>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Condor Report — {_e(result.target)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="header">
  <h1>🦅 Condor Security Report</h1>
  <div class="meta">{meta_html}</div>
</div>
<div class="summary">{summary_badges or '<span style="color:#27ae60;font-weight:600">✅ Clean</span>'}</div>
{body_html}
</body>
</html>"""
