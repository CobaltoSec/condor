"""Tests for compliance-grouped HTML report."""
import re

import pytest

from condor.compliance_report import to_compliance_html
from condor.core.models import Finding, OWASPCategory, ScanResult, Severity


def _result(**kwargs) -> ScanResult:
    defaults = dict(target="http://localhost:3000", platform="flowise", modules_run=["goal-hijack"])
    defaults.update(kwargs)
    return ScanResult(**defaults)


def _finding(**kwargs) -> Finding:
    defaults = dict(
        title="Test Finding",
        severity=Severity.HIGH,
        owasp_id=OWASPCategory.ASI01,
        description="A test description.",
        endpoint="/api/test",
        confidence=80,
    )
    defaults.update(kwargs)
    return Finding(**defaults)


# 1. No findings — generates HTML without crash, reports 0 findings
def test_no_findings_generates_html():
    result = _result(findings=[])
    out = to_compliance_html(result, "flowise")
    assert isinstance(out, str)
    assert out.strip().startswith("<!DOCTYPE html")
    assert "0" in out  # 0 findings in executive summary


def test_no_findings_zero_kpis():
    result = _result(findings=[])
    out = to_compliance_html(result, "flowise")
    # kpi-num should show 0 for total findings
    assert ">0<" in out


# 2. Findings from different ASI categories appear grouped by framework
def test_multiple_asi_categories_in_frameworks():
    findings = [
        _finding(title="Injection Attack", owasp_id=OWASPCategory.ASI01, severity=Severity.CRITICAL),
        _finding(title="Tool Misuse", owasp_id=OWASPCategory.ASI02, severity=Severity.HIGH),
        _finding(title="Supply Chain", owasp_id=OWASPCategory.ASI04, severity=Severity.MEDIUM),
    ]
    result = _result(findings=findings)
    out = to_compliance_html(result, "flowise")
    # All three framework sections must be present
    assert "NIST AI RMF" in out
    assert "ISO/IEC 42001" in out
    assert "EU AI Act" in out
    # Finding titles must appear
    assert "Injection Attack" in out
    assert "Tool Misuse" in out
    assert "Supply Chain" in out


# 3. HTML is self-contained — no external src= or href= references
def test_html_self_contained():
    result = _result(findings=[_finding()])
    out = to_compliance_html(result, "flowise")
    # No external script src
    external_src = re.findall(r'src=["\']https?://', out)
    assert not external_src, f"Found external src: {external_src}"
    # No external stylesheet href
    external_href = re.findall(r'<link[^>]+href=["\']https?://', out)
    assert not external_href, f"Found external href: {external_href}"


# 4. Executive summary shows correct numbers
def test_executive_summary_counts():
    findings = [
        _finding(title="F1", owasp_id=OWASPCategory.ASI01),
        _finding(title="F2", owasp_id=OWASPCategory.ASI03),
    ]
    result = _result(findings=findings)
    out = to_compliance_html(result, "generic")
    # 2 total findings
    assert ">2<" in out
    # At least 1 framework affected (all 3 frameworks map ASI01 and ASI03)
    assert ">3<" in out  # 3 frameworks affected


# 5. Critical findings appear highlighted (severity badge in output)
def test_critical_finding_badge_present():
    findings = [
        _finding(title="Critical Injection", severity=Severity.CRITICAL, owasp_id=OWASPCategory.ASI01),
    ]
    result = _result(findings=findings)
    out = to_compliance_html(result, "flowise")
    assert "Critical Injection" in out
    assert "CRITICAL" in out
