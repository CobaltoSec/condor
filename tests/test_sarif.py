"""Tests for SARIF 2.1.0 serialization."""
import pytest

from condor.core.models import AgentSurface, Finding, OWASPCategory, Severity, ScanResult
from condor.sarif import to_sarif


def _make_surface():
    return AgentSurface(platform="flowise", base_url="http://localhost:3000")


def _make_result(findings=None, target="http://target:3000"):
    return ScanResult(
        target=target,
        platform="flowise",
        findings=findings or [],
        modules_run=["goal-hijack"],
        surface=_make_surface(),
    )


def _make_finding(
    severity=Severity.HIGH,
    owasp_id=OWASPCategory.ASI01,
    endpoint="/api/test",
    confidence=80,
):
    return Finding(
        title="Test finding",
        severity=severity,
        owasp_id=owasp_id,
        description="Test description",
        evidence="Test evidence",
        remediation="Test remediation",
        confidence=confidence,
        endpoint=endpoint,
    )


def test_empty_findings_produces_valid_sarif():
    sarif = to_sarif(_make_result(), tool_version="0.1.0")
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "condor"
    assert sarif["runs"][0]["tool"]["driver"]["version"] == "0.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


def test_critical_and_high_map_to_error():
    for sev in (Severity.CRITICAL, Severity.HIGH):
        result = _make_result([_make_finding(sev)])
        sarif = to_sarif(result, "0.1.0")
        assert sarif["runs"][0]["results"][0]["level"] == "error"


def test_medium_maps_to_warning():
    result = _make_result([_make_finding(Severity.MEDIUM)])
    sarif = to_sarif(result, "0.1.0")
    assert sarif["runs"][0]["results"][0]["level"] == "warning"


def test_low_and_info_map_to_note():
    for sev in (Severity.LOW, Severity.INFO):
        result = _make_result([_make_finding(sev)])
        sarif = to_sarif(result, "0.1.0")
        assert sarif["runs"][0]["results"][0]["level"] == "note"


def test_uri_construction():
    finding = _make_finding(endpoint="/api/v1/chatflows")
    result = _make_result([finding], target="http://target:3000")
    sarif = to_sarif(result, "0.1.0")
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "http://target:3000/api/v1/chatflows"


def test_rule_deduplication():
    findings = [
        _make_finding(owasp_id=OWASPCategory.ASI01),
        _make_finding(owasp_id=OWASPCategory.ASI01),
        _make_finding(owasp_id=OWASPCategory.ASI02),
    ]
    result = _make_result(findings)
    sarif = to_sarif(result, "0.1.0")
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    assert rule_ids.count("ASI01") == 1
    assert "ASI02" in rule_ids
    assert len(rules) == 2


def test_confidence_in_partial_fingerprints():
    finding = _make_finding(confidence=92)
    result = _make_result([finding])
    sarif = to_sarif(result, "0.1.0")
    fp = sarif["runs"][0]["results"][0]["partialFingerprints"]
    assert fp["condorConfidence"] == "92"


def test_message_text_contains_title_prefix():
    finding = Finding(
        title="My Title",
        severity=Severity.HIGH,
        owasp_id=OWASPCategory.ASI01,
        description="some description",
        endpoint="/test",
    )
    result = _make_result([finding])
    sarif = to_sarif(result, "0.1.0")
    msg = sarif["runs"][0]["results"][0]["message"]["text"]
    assert msg.startswith("[My Title]")
    assert "some description" in msg


def test_rule_help_contains_remediation():
    finding = Finding(
        title="T",
        severity=Severity.HIGH,
        owasp_id=OWASPCategory.ASI02,
        description="d",
        remediation="Sanitize all inputs carefully.",
        endpoint="/test",
    )
    result = _make_result([finding])
    sarif = to_sarif(result, "0.1.0")
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    rule = next(r for r in rules if r["id"] == "ASI02")
    assert rule["help"]["text"] == "Sanitize all inputs carefully."


def test_rule_tags_include_cwe():
    finding = Finding(
        title="T",
        severity=Severity.HIGH,
        owasp_id=OWASPCategory.ASI03,
        description="d",
        cwe_id="CWE-306",
        endpoint="/test",
    )
    result = _make_result([finding])
    sarif = to_sarif(result, "0.1.0")
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    rule = next(r for r in rules if r["id"] == "ASI03")
    assert "CWE-306" in rule["properties"]["tags"]
    assert "security" in rule["properties"]["tags"]


def test_rule_tags_security_always_present():
    finding = _make_finding()
    result = _make_result([finding])
    sarif = to_sarif(result, "0.1.0")
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert "security" in rules[0]["properties"]["tags"]
