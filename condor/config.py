"""condor.yaml / .condor.yaml configuration file support."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


_CONFIG_CANDIDATES = [
    Path("condor.yaml"),
    Path(".condor.yaml"),
    Path("condor.yml"),
    Path(".condor.yml"),
]


def load_config(path: Path | None = None) -> dict[str, Any]:
    """Load configuration from condor.yaml or the specified path.

    Priority order (highest to lowest): CLI flags > env vars > config file > hardcoded defaults.
    This function returns only the config file values; CLI/env merging happens in cli.py.
    """
    candidates = []
    if path:
        candidates.append(path)
    candidates.extend(_CONFIG_CANDIDATES)
    home_cfg = Path.home() / ".condor.yaml"
    candidates.append(home_cfg)

    for p in candidates:
        if p.exists():
            try:
                raw = yaml.safe_load(p.read_text(encoding="utf-8"))
                return raw if isinstance(raw, dict) else {}
            except Exception:
                return {}
    return {}


def apply_config_defaults(config: dict[str, Any], **cli_values: Any) -> dict[str, Any]:
    """Return cli_values with None entries filled in from config.

    Only fills in values that are None in cli_values (i.e. were not explicitly set by the user).
    Boolean flags with a False default cannot be distinguished from 'not set', so they are
    not overridden from config.
    """
    result = dict(cli_values)
    for key, val in result.items():
        if val is None and key in config:
            result[key] = config[key]
    return result
