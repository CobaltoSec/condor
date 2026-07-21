"""Compliance-grouped HTML report for Condor scan results."""
from __future__ import annotations

import html
from collections import defaultdict

from .compliance import get_compliance_refs
from .core.models import Finding, ScanResult, Severity

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

_SEV_COLORS = {
    "critical": "#c0392b",
    "high":     "#e74c3c",
    "medium":   "#e67e22",
    "low":      "#3498db",
    "info":     "#7f8c8d",
}

_FRAMEWORK_META = {
    "nist_ai_rmf": {
        "label":  "NIST AI RMF",
        "color":  "#1e8449",
        "accent": "#27ae60",
        "bg":     "#eafaf1",
        "dark_bg": "#0d3b1f",
    },
    "iso_42001": {
        "label":  "ISO/IEC 42001",
        "color":  "#1a5276",
        "accent": "#2980b9",
        "bg":     "#eaf4fb",
        "dark_bg": "#0a2a40",
    },
    "eu_ai_act": {
        "label":  "EU AI Act",
        "color":  "#784212",
        "accent": "#ca6f1e",
        "bg":     "#fef5e7",
        "dark_bg": "#3b2008",
    },
}

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       background: #f5f6fa; color: #2c3e50; padding: 2rem; }
a { color: inherit; }
.header { background: #1a1a2e; color: #fff; border-radius: 8px;
          padding: 1.5rem 2rem; margin-bottom: 1.5rem; }
.header h1 { font-size: 1.6rem; margin-bottom: 0.4rem; }
.header .meta { font-size: 0.85rem; color: #bdc3c7; line-height: 1.8; }
.exec-summary { background: #fff; border-radius: 8px; padding: 1.5rem 2rem;
                margin-bottom: 1.5rem; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }
.exec-summary h2 { font-size: 1.1rem; margin-bottom: 1rem; color: #1a1a2e; }
.kpi-row { display: flex; gap: 1.2rem; flex-wrap: wrap; margin-bottom: 0; }
.kpi { background: #f8f9fa; border-radius: 6px; padding: 0.8rem 1.4rem;
       text-align: center; min-width: 110px; border: 1px solid #e0e0e0; }
.kpi .kpi-num { font-size: 2rem; font-weight: 700; line-height: 1; color: #1a1a2e; }
.kpi .kpi-lbl { font-size: 0.72rem; color: #7f8c8d; margin-top: 3px;
                text-transform: uppercase; letter-spacing: 0.05em; }
.framework-section { margin-bottom: 2rem; }
.framework-header { border-radius: 6px 6px 0 0; padding: 0.9rem 1.2rem;
                    color: #fff; font-size: 1rem; font-weight: 700; }
.ctrl-table { width: 100%; border-collapse: collapse; background: #fff;
              box-shadow: 0 1px 4px rgba(0,0,0,0.08);
              border-radius: 0 0 6px 6px; overflow: hidden; }
.ctrl-table thead th { background: #2c3e50; color: #fff; padding: 0.65rem 1rem;
                        text-align: left; font-size: 0.78rem;
                        text-transform: uppercase; letter-spacing: 0.05em; }
.ctrl-table tbody tr:nth-child(even) { background: #fafbfc; }
.ctrl-table tbody tr:hover { background: #eaf4fd; }
td { padding: 0.6rem 1rem; font-size: 0.87rem; vertical-align: top; }
.ctrl-id { font-family: monospace; font-size: 0.8rem; font-weight: 700;
           white-space: nowrap; }
.finding-list { list-style: none; }
.finding-list li { padding: 2px 0; }
.sev-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%;
           margin-right: 5px; vertical-align: middle; }
.sev-badge { display: inline-block; border-radius: 4px; padding: 1px 6px;
             color: #fff; font-size: 0.68rem; font-weight: 700;
             letter-spacing: 0.04em; vertical-align: middle; margin-right: 4px; }
.max-sev { display: inline-block; border-radius: 4px; padding: 2px 8px;
           color: #fff; font-size: 0.75rem; font-weight: 700; }
.no-findings { background: #d5f5e3; border: 1px solid #27ae60; border-radius: 8px;
               padding: 1.5rem 2rem; color: #1e8449; font-weight: 600; }
@media (prefers-color-scheme: dark) {
  body { background: #1a1a2e; color: #ecf0f1; }
  .exec-summary { background: #16213e; box-shadow: 0 1px 4px rgba(0,0,0,0.4); }
  .exec-summary h2 { color: #ecf0f1; }
  .kpi { background: #0f3460; border-color: #1a4a7a; }
  .kpi .kpi-num { color: #ecf0f1; }
  .ctrl-table { background: #16213e; box-shadow: 0 1px 4px rgba(0,0,0,0.4); }
  .ctrl-table tbody tr:nth-child(even) { background: #0f3460; }
  .ctrl-table tbody tr:hover { background: #1a4a7a; }
  .no-findings { background: #1e4d2b; border-color: #27ae60; color: #58d68d; }
}
:root[data-theme="dark"] body { background: #1a1a2e; color: #ecf0f1; }
:root[data-theme="light"] body { background: #f5f6fa; color: #2c3e50; }
:root[data-theme="dark"] .exec-summary { background: #16213e; }
:root[data-theme="dark"] .kpi { background: #0f3460; border-color: #1a4a7a; }
:root[data-theme="dark"] .kpi .kpi-num { color: #ecf0f1; }
:root[data-theme="dark"] .ctrl-table { background: #16213e; }
:root[data-theme="dark"] .ctrl-table tbody tr:nth-child(even) { background: #0f3460; }
"""


def _e(text: str) -> str:
    return html.escape(str(text), quote=True)


def _sev_color(sev: Severity) -> str:
    return _SEV_COLORS.get(sev.value, "#7f8c8d")


def _max_severity(findings: list[Finding]) -> Severity | None:
    if not findings:
        return None
    return min(findings, key=lambda f: _SEV_ORDER.index(f.severity)).severity


def _build_framework_map(findings: list[Finding]) -> dict[str, dict[str, list[Finding]]]:
    """
    Returns {framework_key: {control_id: [findings, ...]}}
    """
    result: dict[str, dict[str, list[Finding]]] = {k: defaultdict(list) for k in _FRAMEWORK_META}
    for finding in findings:
        refs = get_compliance_refs(finding.owasp_id.value)
        for framework_key in _FRAMEWORK_META:
            for control in refs.get(framework_key, []):
                result[framework_key][control].append(finding)
    return result


def _framework_section_html(framework_key: str, ctrl_map: dict[str, list[Finding]]) -> str:
    meta = _FRAMEWORK_META[framework_key]
    header = (
        f'<div class="framework-header" style="background:{meta["color"]}">'
        f'{_e(meta["label"])}'
        f'</div>'
    )

    if not ctrl_map:
        table = (
            '<table class="ctrl-table">'
            '<tbody><tr><td colspan="3" style="color:#7f8c8d;font-style:italic">'
            'No controls violated.</td></tr></tbody>'
            '</table>'
        )
    else:
        rows = ""
        for ctrl_id in sorted(ctrl_map.keys()):
            ctrl_findings = ctrl_map[ctrl_id]
            max_sev = _max_severity(ctrl_findings)
            max_sev_badge = ""
            if max_sev:
                color = _sev_color(max_sev)
                max_sev_badge = (
                    f'<span class="max-sev" style="background:{color}">'
                    f'{_e(max_sev.value.upper())}</span>'
                )
            finding_items = ""
            for f in sorted(ctrl_findings, key=lambda x: _SEV_ORDER.index(x.severity)):
                sev_color = _sev_color(f.severity)
                sev_badge = (
                    f'<span class="sev-badge" style="background:{sev_color}">'
                    f'{_e(f.severity.value.upper())}</span>'
                )
                finding_items += f'<li>{sev_badge} {_e(f.title)}</li>\n'
            rows += (
                f'<tr>'
                f'<td class="ctrl-id">{_e(ctrl_id)}</td>'
                f'<td><ul class="finding-list">{finding_items}</ul></td>'
                f'<td style="text-align:center">{max_sev_badge}</td>'
                f'</tr>\n'
            )
        table = (
            '<table class="ctrl-table">'
            '<thead><tr>'
            '<th>Control</th>'
            '<th>Findings</th>'
            '<th style="text-align:center">Max Severity</th>'
            '</tr></thead>'
            f'<tbody>{rows}</tbody>'
            '</table>'
        )

    return f'<div class="framework-section">{header}{table}</div>'


def to_compliance_html(result: ScanResult, platform: str) -> str:
    """Render a compliance-grouped HTML report from a ScanResult."""
    findings = result.findings
    fw_map = _build_framework_map(findings)

    # Executive summary stats
    total_findings = len(findings)
    violated_controls: dict[str, set[str]] = {}
    frameworks_hit = 0
    total_ctrl_violated = 0
    for fw_key, ctrl_map in fw_map.items():
        controls_violated = set(ctrl_map.keys())
        violated_controls[fw_key] = controls_violated
        if controls_violated:
            frameworks_hit += 1
        total_ctrl_violated += len(controls_violated)

    # KPI row
    kpi_html = (
        f'<div class="kpi"><div class="kpi-num">{total_findings}</div>'
        f'<div class="kpi-lbl">Total Findings</div></div>'
        f'<div class="kpi"><div class="kpi-num">{frameworks_hit}</div>'
        f'<div class="kpi-lbl">Frameworks Affected</div></div>'
        f'<div class="kpi"><div class="kpi-num">{total_ctrl_violated}</div>'
        f'<div class="kpi-lbl">Controls Violated</div></div>'
    )

    # Per-framework KPIs
    for fw_key, meta in _FRAMEWORK_META.items():
        n = len(violated_controls.get(fw_key, set()))
        kpi_html += (
            f'<div class="kpi" style="border-top:3px solid {meta["accent"]}">'
            f'<div class="kpi-num" style="color:{meta["color"]}">{n}</div>'
            f'<div class="kpi-lbl">{_e(meta["label"])}</div></div>'
        )

    exec_summary = (
        '<div class="exec-summary">'
        '<h2>Executive Summary</h2>'
        f'<div class="kpi-row">{kpi_html}</div>'
        '</div>'
    )

    if not findings:
        body = '<div class="no-findings">No findings detected — target appears clean for the modules run.</div>'
    else:
        body = ""
        for fw_key in ("nist_ai_rmf", "iso_42001", "eu_ai_act"):
            body += _framework_section_html(fw_key, fw_map[fw_key])

    meta_parts = [
        f"Target: {_e(result.target)}",
        f"Platform: {_e(platform)}",
    ]
    if result.started_at:
        meta_parts.append(f"Date: {result.started_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    if result.duration_seconds is not None:
        meta_parts.append(f"Duration: {result.duration_seconds:.1f}s")

    meta_html = " &nbsp;&middot;&nbsp; ".join(meta_parts)

    footer = (
        f'<p style="margin-top:2rem;font-size:0.8rem;color:#7f8c8d">'
        f'{total_ctrl_violated} control(s) violated across {frameworks_hit} framework(s) '
        f'&mdash; {total_findings} finding(s) total</p>'
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Condor Compliance Report &mdash; {_e(result.target)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="header">
  <h1>Condor Compliance Report</h1>
  <div class="meta">{meta_html}</div>
</div>
{exec_summary}
{body}
{footer}
</body>
</html>"""
