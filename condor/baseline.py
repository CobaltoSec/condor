"""Baseline/suppression system — fingerprint known findings to suppress in CI/CD."""
from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path

from .core.models import Finding, ScanResult


def compute_fingerprint(finding: Finding) -> str:
    key = f"{finding.owasp_id}|{finding.title}|{finding.endpoint}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def load_baseline(path: Path) -> set[str]:
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return {entry["fingerprint"] for entry in data.get("fingerprints", [])}
    except Exception:
        return set()


def save_baseline(result: ScanResult, path: Path) -> None:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    entries = [
        {
            "fingerprint": compute_fingerprint(f),
            "title": f.title,
            "owasp_id": f.owasp_id.value,
            "endpoint": f.endpoint,
            "suppressed_at": now,
        }
        for f in result.findings
    ]
    payload = {"version": "1", "created_at": now, "fingerprints": entries}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def apply_baseline(result: ScanResult, baseline: set[str]) -> ScanResult:
    kept = [f for f in result.findings if compute_fingerprint(f) not in baseline]
    suppressed = len(result.findings) - len(kept)
    surface = result.surface.model_copy(
        update={"raw_info": {**result.surface.raw_info, "suppressed_count": suppressed}}
    ) if result.surface else None
    return result.model_copy(update={"findings": kept, "surface": surface})
