"""Tests for condor.remediation module."""
from condor.core.models import Finding, OWASPCategory, Severity
from condor.remediation import enrich_findings, get_platform_fix


def _finding(owasp_id: OWASPCategory, remediation: str = "") -> Finding:
    return Finding(
        title="Test finding",
        severity=Severity.HIGH,
        owasp_id=owasp_id,
        description="desc",
        remediation=remediation,
        endpoint="/api/test",
    )


def test_get_fix_known_platform():
    fix = get_platform_fix("ASI03", "flowise")
    assert fix is not None
    assert "title" in fix
    assert "code" in fix
    assert "FLOWISE_USERNAME" in fix["code"]


def test_get_fix_generic_fallback():
    fix = get_platform_fix("ASI03", "unknown-platform")
    assert fix is not None
    assert "title" in fix
    assert "code" in fix


def test_get_fix_no_entry():
    # ASI04 only has generic; crewai has no entry and generic exists → should return generic
    # We need a case where there is truly no entry at all — use a made-up ASI ID
    fix = get_platform_fix("ASI99", "crewai")
    assert fix is None


def test_get_fix_specific_beats_generic():
    flowise_fix = get_platform_fix("ASI03", "flowise")
    generic_fix = get_platform_fix("ASI03", "generic")
    assert flowise_fix is not None
    assert generic_fix is not None
    assert flowise_fix["code"] != generic_fix["code"]


def test_enrich_findings_appends_remediation():
    f = _finding(OWASPCategory.ASI03)
    result = enrich_findings([f], "flowise")
    assert len(result) == 1
    assert "FLOWISE_USERNAME" in result[0].remediation


def test_enrich_findings_fallback():
    f = _finding(OWASPCategory.ASI01)
    result = enrich_findings([f], "unknown-platform-xyz")
    assert len(result) == 1
    # ASI01 has a generic entry
    assert result[0].remediation != ""


def test_enrich_findings_no_mutation():
    f = _finding(OWASPCategory.ASI03)
    original_remediation = f.remediation
    enrich_findings([f], "flowise")
    assert f.remediation == original_remediation


def test_enrich_findings_empty_list():
    result = enrich_findings([], "flowise")
    assert result == []


def test_enrich_preserves_original_remediation():
    existing = "Original remediation text."
    f = _finding(OWASPCategory.ASI03, remediation=existing)
    result = enrich_findings([f], "flowise")
    assert result[0].remediation.startswith(existing)
    assert "FLOWISE_USERNAME" in result[0].remediation


def test_enrich_no_fix_returns_original():
    # ASI02 now has a generic entry; a platform not in the specific list falls back to generic
    f = _finding(OWASPCategory.ASI02)
    result = enrich_findings([f], "crewai")
    assert "Sanitize tool parameter inputs" in result[0].remediation


def test_enrich_multiple_findings():
    findings = [
        _finding(OWASPCategory.ASI01),
        _finding(OWASPCategory.ASI03),
        _finding(OWASPCategory.ASI06),
    ]
    result = enrich_findings(findings, "flowise")
    assert len(result) == 3
    for r in result:
        assert r.remediation != "" or r.owasp_id == OWASPCategory.ASI01
