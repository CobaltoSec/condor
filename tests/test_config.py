"""Tests for condor.config."""
from pathlib import Path

import pytest
import yaml

from condor.config import apply_config_defaults, load_config


def _write_yaml(path: Path, data: object) -> None:
    path.write_text(yaml.dump(data), encoding="utf-8")


# ── load_config ───────────────────────────────────────────────────────────────


def test_load_config_no_file(tmp_path, monkeypatch):
    """No config file anywhere → returns empty dict, no crash."""
    monkeypatch.setattr("condor.config._CONFIG_CANDIDATES", [tmp_path / "nonexistent.yaml"])
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    result = load_config()
    assert result == {}


def test_load_config_explicit_path(tmp_path):
    """Explicit path to valid yaml → values loaded correctly."""
    cfg_file = tmp_path / "my_config.yaml"
    _write_yaml(cfg_file, {"url": "http://localhost:3000", "platform": "flowise"})
    result = load_config(path=cfg_file)
    assert result["url"] == "http://localhost:3000"
    assert result["platform"] == "flowise"


def test_load_config_invalid_yaml(tmp_path):
    """Malformed yaml → returns empty dict, no exception raised."""
    cfg_file = tmp_path / "bad.yaml"
    cfg_file.write_text("key: [unclosed\nnot: valid:", encoding="utf-8")
    result = load_config(path=cfg_file)
    assert result == {}


def test_load_config_valid_fields(tmp_path):
    """Known config fields (url, platform, format, min_severity, timeout) all load."""
    cfg_file = tmp_path / "condor.yaml"
    data = {
        "url": "http://target:8080",
        "platform": "langflow",
        "format": "sarif",
        "min_severity": "HIGH",
        "timeout": 30,
    }
    _write_yaml(cfg_file, data)
    result = load_config(path=cfg_file)
    assert result["url"] == "http://target:8080"
    assert result["platform"] == "langflow"
    assert result["format"] == "sarif"
    assert result["min_severity"] == "HIGH"
    assert result["timeout"] == 30


def test_load_config_unknown_fields(tmp_path):
    """YAML with unknown fields → no crash, all fields returned as-is."""
    cfg_file = tmp_path / "condor.yaml"
    data = {
        "url": "http://target",
        "totally_unknown_key": "some_value",
        "another_bogus_field": 42,
    }
    _write_yaml(cfg_file, data)
    result = load_config(path=cfg_file)
    assert result["url"] == "http://target"
    assert result["totally_unknown_key"] == "some_value"
    assert result["another_bogus_field"] == 42


def test_load_config_home_fallback(tmp_path, monkeypatch):
    """No local config → falls back to ~/.condor.yaml."""
    monkeypatch.setattr("condor.config._CONFIG_CANDIDATES", [tmp_path / "nonexistent.yaml"])
    home_cfg = tmp_path / ".condor.yaml"
    _write_yaml(home_cfg, {"url": "http://home-fallback"})
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    result = load_config()
    assert result["url"] == "http://home-fallback"


def test_load_config_empty_yaml(tmp_path):
    """Empty yaml file → returns empty dict, no crash."""
    cfg_file = tmp_path / "condor.yaml"
    cfg_file.write_text("", encoding="utf-8")
    result = load_config(path=cfg_file)
    assert result == {}


def test_load_config_non_dict_yaml(tmp_path):
    """YAML that parses to a non-dict (list, scalar) → returns empty dict."""
    cfg_file = tmp_path / "condor.yaml"
    cfg_file.write_text("- item1\n- item2\n", encoding="utf-8")
    result = load_config(path=cfg_file)
    assert result == {}


# ── apply_config_defaults ─────────────────────────────────────────────────────


def test_apply_config_defaults_fills_none_values():
    """CLI args that are None get filled in from config."""
    config = {"url": "http://from-config", "platform": "dify", "format": "json"}
    result = apply_config_defaults(config, url=None, platform=None, format=None)
    assert result["url"] == "http://from-config"
    assert result["platform"] == "dify"
    assert result["format"] == "json"


def test_apply_config_defaults_cli_takes_priority():
    """Explicit CLI values (non-None) override config file values."""
    config = {"url": "http://from-config", "platform": "flowise"}
    result = apply_config_defaults(config, url="http://from-cli", platform=None)
    assert result["url"] == "http://from-cli"
    assert result["platform"] == "flowise"


def test_apply_config_defaults_missing_config_key():
    """Config key not present → CLI None stays None, no KeyError."""
    config = {"url": "http://target"}
    result = apply_config_defaults(config, url=None, platform=None)
    assert result["url"] == "http://target"
    assert result["platform"] is None
