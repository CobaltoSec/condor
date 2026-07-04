"""Basic model tests."""
import pytest
from condor.core.models import Finding, Severity, OWASPCategory, AgentSurface, ScanResult


def test_finding_construction():
    f = Finding(
        title="Test finding",
        severity=Severity.HIGH,
        owasp_id=OWASPCategory.ASI03,
        description="Test description",
    )
    assert f.severity == Severity.HIGH
    assert f.owasp_id == OWASPCategory.ASI03
    assert f.confidence == 80


def test_finding_confidence_clamped():
    f = Finding(title="x", severity=Severity.LOW, owasp_id=OWASPCategory.ASI01, description="x", confidence=150)
    assert f.confidence == 100
    f2 = Finding(title="x", severity=Severity.LOW, owasp_id=OWASPCategory.ASI01, description="x", confidence=-5)
    assert f2.confidence == 0


def test_owasp_categories():
    assert len(OWASPCategory) == 10
    assert OWASPCategory.ASI01.value == "ASI01"
    assert OWASPCategory.ASI10.value == "ASI10"


def test_agent_surface_defaults():
    s = AgentSurface(platform="flowise", base_url="http://localhost:3000")
    assert s.auth_required is False
    assert s.flows == []
    assert s.tools == []


def test_scan_result_finding_count():
    findings = [
        Finding(title="a", severity=Severity.CRITICAL, owasp_id=OWASPCategory.ASI03, description="x"),
        Finding(title="b", severity=Severity.HIGH,     owasp_id=OWASPCategory.ASI05, description="x"),
        Finding(title="c", severity=Severity.HIGH,     owasp_id=OWASPCategory.ASI01, description="x"),
    ]
    result = ScanResult(target="http://localhost:3000", platform="flowise", findings=findings)
    assert result.finding_count == {"critical": 1, "high": 2}


def test_scan_result_empty():
    result = ScanResult(target="http://localhost:3000", platform="generic")
    assert result.finding_count == {}
    assert result.findings == []
