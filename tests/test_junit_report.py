"""Tests for JUnit XML report generation."""
import xml.etree.ElementTree as ET

from condor.core.models import Finding, OWASPCategory, ScanResult, Severity
from condor.junit_report import to_junit


def _result(**kwargs) -> ScanResult:
    defaults = {"target": "http://target", "platform": "generic"}
    defaults.update(kwargs)
    return ScanResult(**defaults)


def _finding(severity=Severity.HIGH, owasp_id=OWASPCategory.ASI01, **kwargs) -> Finding:
    defaults = {
        "title": "Test finding",
        "severity": severity,
        "owasp_id": owasp_id,
        "description": "Test description",
        "endpoint": "/api/v1/test",
    }
    defaults.update(kwargs)
    return Finding(**defaults)


def test_valid_xml():
    result = _result(findings=[_finding()])
    xml_str = to_junit(result)
    root = ET.fromstring(xml_str)
    assert root.tag == "testsuites"


def test_finding_as_testcase():
    result = _result(findings=[_finding(title="Goal hijack", severity=Severity.HIGH)])
    root = ET.fromstring(to_junit(result))
    testcases = root.findall(".//testcase")
    assert len(testcases) == 1
    failures = testcases[0].findall("failure")
    assert len(failures) == 1
    assert "HIGH" in testcases[0].attrib["name"]


def test_grouped_by_owasp():
    findings = [
        _finding(owasp_id=OWASPCategory.ASI01, title="A"),
        _finding(owasp_id=OWASPCategory.ASI02, title="B"),
    ]
    root = ET.fromstring(to_junit(_result(findings=findings)))
    suites = root.findall("testsuite")
    names = {s.attrib["name"] for s in suites}
    assert "condor.ASI01" in names
    assert "condor.ASI02" in names


def test_no_findings_passes():
    root = ET.fromstring(to_junit(_result(findings=[])))
    assert root.attrib["tests"] == "1"
    assert root.attrib["failures"] == "0"
    testcases = root.findall(".//testcase")
    assert len(testcases) == 1
    assert not testcases[0].findall("failure")


def test_failure_count():
    findings = [
        _finding(severity=Severity.HIGH, title="H1"),
        _finding(severity=Severity.HIGH, title="H2"),
        _finding(severity=Severity.LOW, title="L1"),
    ]
    root = ET.fromstring(to_junit(_result(findings=findings)))
    assert root.attrib["failures"] == "2"
    assert root.attrib["tests"] == "3"


def test_xml_escaping():
    f = _finding(evidence='payload: <script>alert("xss")</script> & more')
    xml_str = to_junit(_result(findings=[f]))
    root = ET.fromstring(xml_str)
    failure = root.find(".//failure")
    assert failure is not None
    assert "<script>" in failure.text


def test_duration_in_time_attr():
    result = _result(findings=[_finding()], duration_seconds=5.3)
    root = ET.fromstring(to_junit(result))
    assert root.attrib["time"] == "5.3"


def test_critical_type_security_finding():
    f = _finding(severity=Severity.CRITICAL)
    root = ET.fromstring(to_junit(_result(findings=[f])))
    failure = root.find(".//failure")
    assert failure.attrib["type"] == "SecurityFinding"


def test_medium_type_warning():
    f = _finding(severity=Severity.MEDIUM)
    root = ET.fromstring(to_junit(_result(findings=[f])))
    failure = root.find(".//failure")
    assert failure.attrib["type"] == "Warning"


def test_evidence_in_failure_body():
    f = _finding(evidence="Found token: abc123", remediation="Rotate the token")
    root = ET.fromstring(to_junit(_result(findings=[f])))
    failure = root.find(".//failure")
    assert "abc123" in failure.text
    assert "Rotate" in failure.text
