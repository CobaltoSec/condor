"""Tests for HTML report renderer."""
from condor.core.models import AgentSurface, Finding, OWASPCategory, ScanResult, Severity
from condor.html_report import to_html


def _result(**kwargs) -> ScanResult:
    defaults = dict(target="http://localhost:3000", platform="flowise", modules_run=["goal-hijack"])
    defaults.update(kwargs)
    return ScanResult(**defaults)


def _finding(**kwargs) -> Finding:
    defaults = dict(
        title="Test finding",
        severity=Severity.HIGH,
        owasp_id=OWASPCategory.ASI01,
        description="A test description.",
        evidence="some evidence",
        remediation="fix it",
        endpoint="/api/v1/test",
        confidence=85,
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def test_returns_string():
    assert isinstance(to_html(_result(), "1.0.0"), str)


def test_html_doctype():
    out = to_html(_result(), "1.0.0")
    assert out.strip().startswith("<!DOCTYPE html")


def test_contains_target_url():
    out = to_html(_result(target="http://target.example.com"), "1.0.0")
    assert "target.example.com" in out


def test_contains_finding_title():
    r = _result(findings=[_finding(title="Unique injection title XYZ")])
    out = to_html(r, "1.0.0")
    assert "Unique injection title XYZ" in out


def test_severity_badge_present():
    r = _result(findings=[_finding(severity=Severity.CRITICAL)])
    out = to_html(r, "1.0.0")
    assert "CRITICAL" in out


def test_no_findings_message():
    out = to_html(_result(findings=[]), "1.0.0")
    assert "No findings" in out or "Clean" in out or "clean" in out


def test_owasp_id_present():
    r = _result(findings=[_finding(owasp_id=OWASPCategory.ASI01)])
    out = to_html(r, "1.0.0")
    assert "ASI01" in out


def test_all_severities_in_summary():
    findings = [
        _finding(severity=Severity.CRITICAL, title="c"),
        _finding(severity=Severity.HIGH, title="h"),
        _finding(severity=Severity.MEDIUM, title="m"),
        _finding(severity=Severity.LOW, title="l"),
        _finding(severity=Severity.INFO, title="i"),
    ]
    out = to_html(_result(findings=findings), "1.0.0")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        assert sev in out, f"Missing severity: {sev}"


def test_version_present():
    out = to_html(_result(), "2.3.4")
    assert "2.3.4" in out


def test_evidence_escaped():
    r = _result(findings=[_finding(evidence="<script>alert(1)</script>")])
    out = to_html(r, "1.0.0")
    assert "<script>" not in out
    assert "&lt;script&gt;" in out


def test_findings_ordered_by_severity():
    findings = [
        _finding(severity=Severity.INFO, title="info-finding"),
        _finding(severity=Severity.CRITICAL, title="critical-finding"),
    ]
    out = to_html(_result(findings=findings), "1.0.0")
    assert out.index("critical-finding") < out.index("info-finding")


def test_endpoint_shown():
    r = _result(findings=[_finding(endpoint="/api/v1/secret")])
    out = to_html(r, "1.0.0")
    assert "/api/v1/secret" in out


def test_cwe_badge_rendered():
    r = _result(findings=[_finding(cwe_id="CWE-94")])
    out = to_html(r, "1.0.0")
    assert "CWE-94" in out
    assert "cwe-badge" in out


def test_cwe_badge_absent_when_no_cwe():
    r = _result(findings=[_finding(cwe_id=None)])
    out = to_html(r, "1.0.0")
    assert 'class="cwe-badge">CWE-' not in out


def test_compliance_section_rendered():
    r = _result(findings=[_finding(owasp_id=OWASPCategory.ASI01)])
    out = to_html(r, "1.0.0")
    assert "ISO" in out or "NIST" in out or "EU AI Act" in out


def test_compliance_tag_css_class_present():
    r = _result(findings=[_finding(owasp_id=OWASPCategory.ASI05)])
    out = to_html(r, "1.0.0")
    assert "compliance-tag" in out
