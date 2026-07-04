"""Tests for the Condor CLI (SCALE block)."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from typer.testing import CliRunner

from condor.cli import app
from condor.core.models import AgentSurface, Finding, OWASPCategory, Severity

runner = CliRunner()


def _make_surface() -> AgentSurface:
    return AgentSurface(platform="generic", base_url="http://test:3000")


def _make_finding() -> Finding:
    return Finding(
        title="Test finding",
        severity=Severity.HIGH,
        owasp_id=OWASPCategory.ASI01,
        description="desc",
    )


def _mock_platform(findings: list[Finding] | None = None):
    surface = _make_surface()
    plat = AsyncMock()
    plat.__aenter__ = AsyncMock(return_value=plat)
    plat.__aexit__ = AsyncMock(return_value=False)
    plat.health_check = AsyncMock(return_value=True)
    plat.enumerate = AsyncMock(return_value=surface)
    # make run() return findings for any module
    plat.findings = findings or []
    return plat


def _mock_module(findings: list[Finding] | None = None):
    mod = MagicMock()
    mod.owasp_id = OWASPCategory.ASI01
    mod.description = "Test module"
    mod.run = AsyncMock(return_value=findings or [])
    return mod


class TestArgValidation:
    def test_url_and_targets_mutually_exclusive(self, tmp_path):
        targets_file = tmp_path / "targets.txt"
        targets_file.write_text("http://localhost:3001\n")
        result = runner.invoke(app, ["scan", "--url", "http://x", "--targets", str(targets_file)])
        assert result.exit_code == 1
        assert "mutually exclusive" in result.stdout

    def test_neither_url_nor_targets(self):
        result = runner.invoke(app, ["scan"])
        assert result.exit_code == 1
        assert "--url" in result.stdout or "Provide" in result.stdout

    def test_invalid_format(self):
        result = runner.invoke(app, ["scan", "--url", "http://x", "--format", "xml"])
        assert result.exit_code == 1
        assert "Invalid --format" in result.stdout


class TestFormatOption:
    def _run_scan(self, tmp_path: Path, fmt: str, findings=None):
        plat_mock = _mock_platform()
        mod_mock = _mock_module(findings)
        with (
            patch("condor.cli._PLATFORMS", {"generic": lambda *a, **kw: plat_mock}),
            patch("condor.cli._ALL_MODULES", {"goal-hijack": lambda: mod_mock}),
        ):
            return runner.invoke(app, [
                "scan", "--url", "http://test:3000",
                "--format", fmt,
                "--output-dir", str(tmp_path),
            ])

    def test_format_json_writes_report_json(self, tmp_path):
        result = self._run_scan(tmp_path, "json")
        assert result.exit_code == 0
        assert (tmp_path / "report.json").exists()
        assert not (tmp_path / "report.sarif").exists()

    def test_format_sarif_writes_report_sarif(self, tmp_path):
        result = self._run_scan(tmp_path, "sarif")
        assert result.exit_code == 0
        assert (tmp_path / "report.sarif").exists()
        assert not (tmp_path / "report.json").exists()

    def test_format_both_writes_both(self, tmp_path):
        result = self._run_scan(tmp_path, "both")
        assert result.exit_code == 0
        assert (tmp_path / "report.json").exists()
        assert (tmp_path / "report.sarif").exists()

    def test_format_table_writes_no_files(self, tmp_path):
        result = self._run_scan(tmp_path, "table")
        assert result.exit_code == 0
        assert not (tmp_path / "report.json").exists()
        assert not (tmp_path / "report.sarif").exists()


class TestExcludeModule:
    def test_exclude_module_removes_from_active(self, tmp_path):
        plat_mock = _mock_platform()
        mod_a = _mock_module()
        mod_b = _mock_module()
        with (
            patch("condor.cli._PLATFORMS", {"generic": lambda *a, **kw: plat_mock}),
            patch("condor.cli._ALL_MODULES", {"mod-a": lambda: mod_a, "mod-b": lambda: mod_b}),
        ):
            result = runner.invoke(app, [
                "scan", "--url", "http://test:3000",
                "--format", "json",
                "--output-dir", str(tmp_path),
                "--exclude-module", "mod-b",
            ])
        assert result.exit_code == 0
        assert mod_a.run.call_count == 1
        assert mod_b.run.call_count == 0

    def test_unknown_exclude_warns_but_continues(self, tmp_path):
        plat_mock = _mock_platform()
        mod_a = _mock_module()
        with (
            patch("condor.cli._PLATFORMS", {"generic": lambda *a, **kw: plat_mock}),
            patch("condor.cli._ALL_MODULES", {"mod-a": lambda: mod_a}),
        ):
            result = runner.invoke(app, [
                "scan", "--url", "http://test:3000",
                "--format", "json",
                "--output-dir", str(tmp_path),
                "--exclude-module", "nonexistent",
            ])
        assert result.exit_code == 0
        assert "Warning" in result.stdout or "unknown" in result.stdout.lower()


class TestBatchScan:
    def test_batch_scan_runs_all_targets(self, tmp_path):
        targets_file = tmp_path / "targets.txt"
        targets_file.write_text("http://host1:3000 generic\nhttp://host2:3000 generic\n")

        plat_mock = _mock_platform()
        mod_mock = _mock_module()

        with (
            patch("condor.cli._PLATFORMS", {"generic": lambda *a, **kw: _mock_platform()}),
            patch("condor.cli._ALL_MODULES", {"goal-hijack": lambda: _mock_module()}),
        ):
            result = runner.invoke(app, [
                "scan",
                "--targets", str(targets_file),
                "--format", "json",
                "--output-dir", str(tmp_path / "out"),
                "--concurrency", "2",
            ])
        assert result.exit_code == 0

    def test_batch_scan_accepts_concurrency_flag(self, tmp_path):
        targets_file = tmp_path / "targets.txt"
        targets_file.write_text("http://host1:3000\n")
        with (
            patch("condor.cli._PLATFORMS", {"generic": lambda *a, **kw: _mock_platform()}),
            patch("condor.cli._ALL_MODULES", {"goal-hijack": lambda: _mock_module()}),
        ):
            result = runner.invoke(app, [
                "scan",
                "--targets", str(targets_file),
                "--format", "json",
                "--output-dir", str(tmp_path / "out"),
                "--concurrency", "10",
            ])
        assert result.exit_code == 0

    def test_batch_scan_empty_file_exits_1(self, tmp_path):
        targets_file = tmp_path / "targets.txt"
        targets_file.write_text("# only comments\n\n")
        result = runner.invoke(app, ["scan", "--targets", str(targets_file)])
        assert result.exit_code == 1


class TestFailOn:
    def test_fail_on_triggers_exit_1_when_finding_at_threshold(self, tmp_path):
        plat_mock = _mock_platform()
        mod_mock = _mock_module([_make_finding()])
        with (
            patch("condor.cli._PLATFORMS", {"generic": lambda *a, **kw: plat_mock}),
            patch("condor.cli._ALL_MODULES", {"goal-hijack": lambda: mod_mock}),
        ):
            result = runner.invoke(app, [
                "scan", "--url", "http://test:3000",
                "--format", "json",
                "--output-dir", str(tmp_path),
                "--fail-on", "high",
            ])
        assert result.exit_code == 1

    def test_fail_on_no_exit_when_below_threshold(self, tmp_path):
        plat_mock = _mock_platform()
        mod_mock = _mock_module([_make_finding()])  # HIGH finding
        with (
            patch("condor.cli._PLATFORMS", {"generic": lambda *a, **kw: plat_mock}),
            patch("condor.cli._ALL_MODULES", {"goal-hijack": lambda: mod_mock}),
        ):
            result = runner.invoke(app, [
                "scan", "--url", "http://test:3000",
                "--format", "json",
                "--output-dir", str(tmp_path),
                "--fail-on", "critical",  # HIGH doesn't reach CRITICAL threshold
            ])
        assert result.exit_code == 0
