"""Tests for condor.baseline."""
import json
from pathlib import Path

import pytest

from condor.baseline import apply_baseline, compute_fingerprint, load_baseline, save_baseline
from condor.core.models import AgentSurface, Finding, OWASPCategory, ScanResult, Severity


def _finding(**kwargs) -> Finding:
    defaults = dict(
        title="Test finding",
        severity=Severity.HIGH,
        owasp_id=OWASPCategory.ASI01,
        description="desc",
        endpoint="/api/v1/test",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def _result(findings: list[Finding]) -> ScanResult:
    surface = AgentSurface(platform="flowise", base_url="http://localhost:3000")
    return ScanResult(target="http://localhost:3000", platform="flowise", findings=findings, surface=surface)


def test_compute_fingerprint_stable():
    f = _finding()
    assert compute_fingerprint(f) == compute_fingerprint(f)


def test_compute_fingerprint_different_findings():
    f1 = _finding(title="Finding A", endpoint="/ep1")
    f2 = _finding(title="Finding B", endpoint="/ep2")
    assert compute_fingerprint(f1) != compute_fingerprint(f2)


def test_compute_fingerprint_differs_by_owasp_id():
    f1 = _finding(owasp_id=OWASPCategory.ASI01)
    f2 = _finding(owasp_id=OWASPCategory.ASI02)
    assert compute_fingerprint(f1) != compute_fingerprint(f2)


def test_load_baseline_missing_file(tmp_path):
    result = load_baseline(tmp_path / "nonexistent.json")
    assert result == set()


def test_load_baseline_with_entries(tmp_path):
    path = tmp_path / "baseline.json"
    data = {
        "version": "1",
        "created_at": "2026-01-01T00:00:00Z",
        "fingerprints": [
            {"fingerprint": "abc123", "title": "X", "owasp_id": "ASI01", "endpoint": "/ep", "suppressed_at": "2026-01-01T00:00:00Z"},
            {"fingerprint": "def456", "title": "Y", "owasp_id": "ASI02", "endpoint": "/ep2", "suppressed_at": "2026-01-01T00:00:00Z"},
        ],
    }
    path.write_text(json.dumps(data), encoding="utf-8")
    result = load_baseline(path)
    assert result == {"abc123", "def456"}


def test_load_baseline_invalid_json_returns_empty(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("not json", encoding="utf-8")
    assert load_baseline(path) == set()


def test_save_and_load_roundtrip(tmp_path):
    f = _finding(title="Injected", endpoint="/api/v1/prediction/flow1")
    result = _result([f])
    path = tmp_path / "baseline.json"
    save_baseline(result, path)
    loaded = load_baseline(path)
    assert compute_fingerprint(f) in loaded


def test_apply_baseline_removes_suppressed():
    f = _finding(title="Known", endpoint="/ep")
    baseline = {compute_fingerprint(f)}
    result = _result([f])
    filtered = apply_baseline(result, baseline)
    assert filtered.findings == []


def test_apply_baseline_keeps_new_findings():
    known = _finding(title="Known", endpoint="/ep1")
    new = _finding(title="New", endpoint="/ep2")
    baseline = {compute_fingerprint(known)}
    result = _result([known, new])
    filtered = apply_baseline(result, baseline)
    assert len(filtered.findings) == 1
    assert filtered.findings[0].title == "New"


def test_apply_baseline_suppressed_count():
    f1 = _finding(title="A", endpoint="/ep1")
    f2 = _finding(title="B", endpoint="/ep2")
    f3 = _finding(title="C", endpoint="/ep3")
    baseline = {compute_fingerprint(f1)}
    result = _result([f1, f2, f3])
    filtered = apply_baseline(result, baseline)
    assert filtered.surface.raw_info["suppressed_count"] == 1
    assert len(filtered.findings) == 2


def test_apply_baseline_empty_baseline_keeps_all():
    findings = [_finding(title=f"F{i}", endpoint=f"/ep{i}") for i in range(3)]
    result = _result(findings)
    filtered = apply_baseline(result, set())
    assert len(filtered.findings) == 3


def test_save_baseline_creates_parent_dirs(tmp_path):
    f = _finding()
    result = _result([f])
    path = tmp_path / "deep" / "nested" / "baseline.json"
    save_baseline(result, path)
    assert path.exists()
    data = json.loads(path.read_text())
    assert data["version"] == "1"
    assert len(data["fingerprints"]) == 1
