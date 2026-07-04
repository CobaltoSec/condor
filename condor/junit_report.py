"""JUnit XML serialization for Condor scan results."""
from __future__ import annotations

import re
from collections import defaultdict
from xml.sax.saxutils import escape

from .core.models import ScanResult, Severity

_HIGH_SEVERITIES = {Severity.CRITICAL, Severity.HIGH}

_SEVERITY_TO_TYPE: dict[Severity, str] = {
    Severity.CRITICAL: "SecurityFinding",
    Severity.HIGH:     "SecurityFinding",
    Severity.MEDIUM:   "Warning",
    Severity.LOW:      "Info",
    Severity.INFO:     "Info",
}

_SAFE_RE = re.compile(r"[^\w\-.]")


def _sanitize(s: str) -> str:
    return _SAFE_RE.sub("_", s)[:80]


def to_junit(result: ScanResult) -> str:
    """Convert a ScanResult to JUnit XML (compatible with Jenkins, GitLab, CircleCI, GitHub Actions)."""
    duration = str(result.duration_seconds) if result.duration_seconds is not None else "0"

    if not result.findings:
        xml = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<testsuites name="condor" tests="1" failures="0" errors="0" time="{escape(duration)}">\n'
            '  <testsuite name="condor.scan" tests="1" failures="0" time="0">\n'
            '    <testcase name="No security findings detected" classname="condor.clean" time="0"/>\n'
            '  </testsuite>\n'
            '</testsuites>'
        )
        return xml

    by_owasp: dict[str, list] = defaultdict(list)
    for f in result.findings:
        by_owasp[f.owasp_id.value].append(f)

    total_tests    = len(result.findings)
    total_failures = sum(1 for f in result.findings if f.severity in _HIGH_SEVERITIES)

    lines: list[str] = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<testsuites name="condor" tests="{total_tests}" failures="{total_failures}" errors="0" time="{escape(duration)}">',
    ]

    for owasp_id in sorted(by_owasp):
        findings = by_owasp[owasp_id]
        suite_failures = sum(1 for f in findings if f.severity in _HIGH_SEVERITIES)
        lines.append(
            f'  <testsuite name="condor.{escape(owasp_id)}" tests="{len(findings)}" failures="{suite_failures}" time="0">'
        )
        for f in findings:
            sev      = f.severity.value.upper()
            ep       = f.endpoint or result.target
            classname = f"condor.{owasp_id}.{_sanitize(ep)}"
            tc_name  = f"[{sev}] {f.title}"
            msg      = f"{sev} severity finding at {ep}"
            ftype    = _SEVERITY_TO_TYPE[f.severity]
            body_parts = []
            if f.evidence:
                body_parts.append(f"Evidence: {f.evidence}")
            if f.remediation:
                body_parts.append(f"Remediation: {f.remediation}")
            body = escape("\n".join(body_parts)) if body_parts else ""
            lines.append(
                f'    <testcase name="{escape(tc_name)}" classname="{escape(classname)}" time="0">'
            )
            lines.append(
                f'      <failure message="{escape(msg)}" type="{escape(ftype)}">{body}</failure>'
            )
            lines.append("    </testcase>")
        lines.append("  </testsuite>")

    lines.append("</testsuites>")
    return "\n".join(lines)
