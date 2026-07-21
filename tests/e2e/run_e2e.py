#!/usr/bin/env python3
"""
Condor E2E validation — RT-CONDOR-V10-E2E + RT-CONDOR-CS01.

Scans 7 platforms (5 V09 + 2 CS01) and documents findings vs. gaps.

Prerequisites:
    docker compose -f tests/e2e/docker-compose.yml up -d

Usage:
    python tests/e2e/run_e2e.py [--no-wait] [--platform NAME]

Exit codes:
    0  All reachable services scanned successfully
    1  One or more services were unreachable or scan errored
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

HERE = Path(__file__).parent
RESULTS_DIR = HERE / "results"

# ── Finding expectations per platform ─────────────────────────────────────────
# expected_owasp: ASI IDs current condor implementation can detect
# gaps:           what V10-DEEPENED should add (known coverage gaps)

TARGETS = [
    {
        "name": "qdrant",
        "platform": "qdrant",
        "url": "http://localhost:6333",
        "health_url": "http://localhost:6333/healthz",
        "health_timeout": 30,
        # Detected by V10-DEEPENED probes
        "expected_owasp": ["ASI06", "ASI10"],
        "gaps": [
            # SSRF probe fires 404 (collection not pre-loaded → snapshot endpoint not reachable)
            "ASI02 HIGH  — SSRF via /collections/{name}/snapshots/recover: real Qdrant with loaded collections would fire",
        ],
    },
    {
        "name": "chroma",
        "platform": "chroma",
        "url": "http://localhost:8000",
        "health_url": "http://localhost:8000/api/v1/heartbeat",
        "health_timeout": 30,
        # Detected: ASI06 (v2 collections), ASI09 (/openapi.json), ASI10 (409 = endpoint accessible)
        "expected_owasp": ["ASI06", "ASI09", "ASI10"],
        "gaps": [],
    },
    {
        "name": "hayhooks",
        "platform": "hayhooks",
        "url": "http://localhost:1416",
        "health_url": "http://localhost:1416/status",
        "health_timeout": 30,
        # Detected: ASI03 (/status exposes pipeline list), ASI09 (/openapi.json)
        "expected_owasp": ["ASI03", "ASI09"],
        "gaps": [],
    },
    {
        "name": "letta",
        "platform": "letta",
        "url": "http://localhost:8283",
        "health_url": "http://localhost:8283/v1/health",
        "health_timeout": 60,
        # Detected: ASI03 (/v1/agents), ASI04 (tool registry), ASI09 (/openapi.json)
        "expected_owasp": ["ASI03", "ASI04", "ASI09"],
        "gaps": [
            # Probe IDs hardcoded; fresh Letta instance has no agents at those paths
            "ASI06 HIGH  — IDOR on /v1/agents/{id}/memory: probe IDs must match real agent IDs",
        ],
    },
    {
        "name": "open-webui",
        "platform": "openwebui",
        "url": "http://localhost:8080",
        "health_url": "http://localhost:8080/api/v1/models",
        "health_timeout": 180,  # OWI takes ~60s to initialize DB + frontend
        # OWI v0.5.20 serves all GET /api/v1/* routes as SPA HTML (catch-all) →
        # _is_api_response() filters them. POST endpoints return 405 or 403 even
        # with WEBUI_AUTH=False (v0.5.20 enforces auth for write paths despite env var).
        "expected_owasp": ["ASI09"],
        "gaps": [
            "ASI05 CRITICAL — POST /api/v1/functions/create returns 403 (OWI v0.5.20 enforces auth even with WEBUI_AUTH=False)",
            "ASI10 HIGH    — POST /api/v1/tools returns 405 (route mismatch or auth-enforced)",
        ],
    },
    # ── CS03 platforms ──────────────────────────────────────────────────────
    {
        "name": "dify",
        "platform": "dify",
        "url": "http://localhost:5001",
        "health_url": "http://localhost:5001/health",
        "health_timeout": 180,  # migrations run on first boot (60-90s)
        # ASI03: CORS wildcard (CONSOLE_CORS_ALLOW_ORIGINS=*)
        # ASI05: sandbox port 8194 exposed → HIGH + CRITICAL (default key)
        # ASI09: version disclosure via /console/api/version
        "expected_owasp": ["ASI03", "ASI05", "ASI09"],
        "gaps": [],
    },
    # ── CS01 platforms ──────────────────────────────────────────────────────
    {
        "name": "flowise",
        "platform": "flowise",
        "url": "http://localhost:3200",
        "health_url": "http://localhost:3200/api/v1/chatflows",
        "health_timeout": 60,
        # Validated in RT-CONDOR-CFP: 9 findings (3C/5H/1M) against Flowise 1.8.2
        # without auth. ASI03 includes CVE-2026-30820 header bypass probe.
        "expected_owasp": ["ASI01", "ASI02", "ASI03", "ASI09"],
        "gaps": [
            "ASI05 — blind timing probe may vary on cold TCP (warmup request mitigates)",
        ],
    },
    {
        "name": "langflow",
        "platform": "langflow",
        "url": "http://localhost:7860",
        "health_url": "http://localhost:7860/health",
        "health_timeout": 120,
        # LANGFLOW_AUTO_LOGIN=true: simulates misconfigured deployment.
        # ASI09 guaranteed (/api/v1/version, /openapi.json).
        # ASI01/ASI03 depend on whether prediction/flow endpoints are accessible
        # without a token — confirm findings post-scan.
        "expected_owasp": ["ASI09"],
        "gaps": [],
    },
]


def find_condor() -> Path:
    condor_bin = Path(sys.executable).parent / "condor"
    if sys.platform == "win32":
        condor_bin = condor_bin.with_suffix(".exe")
    if condor_bin.exists():
        return condor_bin
    found = shutil.which("condor")
    if found:
        return Path(found)
    sys.exit("ERROR: condor not found. Activate the venv or install condor.")


def wait_for_service(name: str, health_url: str, timeout: int) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with httpx.Client(timeout=3) as client:
                r = client.get(health_url)
                if r.status_code < 500:
                    return True
        except Exception:
            pass
        time.sleep(2)
    return False


def run_scan(condor: Path, target: dict) -> dict | None:
    """Run condor scan, return parsed ScanResult JSON or None on error."""
    cmd = [
        str(condor),
        "scan",
        "--url", target["url"],
        "--platform", target["platform"],
        "--stdout",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return None

    if proc.returncode == 2:
        return None  # platform unreachable or config error

    stdout = proc.stdout.strip()
    if not stdout:
        return None

    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return None


def save_result(name: str, data: dict) -> Path:
    RESULTS_DIR.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = RESULTS_DIR / f"{name}-{ts}.json"
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def print_section(title: str) -> None:
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--no-wait", action="store_true", help="Skip health check wait (assume services are up)")
    parser.add_argument("--platform", metavar="NAME", help="Scan only this platform")
    args = parser.parse_args()

    condor = find_condor()

    targets = TARGETS
    if args.platform:
        targets = [t for t in TARGETS if t["name"] == args.platform]
        if not targets:
            sys.exit(f"ERROR: unknown platform '{args.platform}'. Available: {[t['name'] for t in TARGETS]}")

    print(f"\nCondor E2E — RT-CONDOR-V10-E2E + RT-CONDOR-CS01")
    print(f"Platforms: {', '.join(t['name'] for t in targets)}")
    print(f"Results  : {RESULTS_DIR}")

    rows: list[dict] = []

    for target in targets:
        print_section(f"{target['name']} ({target['platform']})  →  {target['url']}")

        # Health check
        if args.no_wait:
            healthy = True
        else:
            print(f"  Waiting for service (timeout={target['health_timeout']}s)...", end=" ", flush=True)
            healthy = wait_for_service(target["name"], target["health_url"], target["health_timeout"])
            print("UP" if healthy else "TIMEOUT")

        if not healthy:
            rows.append({"name": target["name"], "status": "TIMEOUT", "findings": 0, "owasp": [], "scan_ok": False})
            continue

        # Scan
        print(f"  Running condor scan...", end=" ", flush=True)
        result = run_scan(condor, target)

        if result is None:
            print("ERROR (platform unreachable or scan failed)")
            rows.append({"name": target["name"], "status": "SCAN_ERROR", "findings": 0, "owasp": [], "scan_ok": False})
            continue

        findings = result.get("findings", [])
        found_owasp = sorted({f.get("owasp_id", "?") for f in findings})
        duration = result.get("duration_seconds", 0)
        print(f"{len(findings)} findings  ({duration:.1f}s)")

        # Print each finding
        for f in findings:
            sev = f.get("severity", "?").upper()
            owasp = f.get("owasp_id", "?")
            title = f.get("title", "?")
            print(f"    [{sev}] {owasp}  {title}")

        # Coverage vs. expected
        expected = target.get("expected_owasp", [])
        if expected:
            missing = [e for e in expected if e not in found_owasp]
            if missing:
                print(f"  EXPECTED (not found): {', '.join(missing)}")
            else:
                print(f"  EXPECTED: all {len(expected)} target ASI IDs detected")

        # Document known gaps
        if target.get("gaps"):
            print("  Known gaps (V10-DEEPENED):")
            for gap in target["gaps"]:
                print(f"    - {gap}")

        # Save to disk
        result_path = save_result(target["name"], result)
        print(f"  Saved: {result_path.name}")

        rows.append({
            "name": target["name"],
            "status": "OK",
            "findings": len(findings),
            "owasp": found_owasp,
            "scan_ok": True,
        })

    # Summary table
    print_section("SUMMARY")
    print(f"  {'Platform':<16} {'Status':<12} {'Findings':<10} {'OWASP IDs found'}")
    print(f"  {'─'*16} {'─'*12} {'─'*10} {'─'*30}")
    for row in rows:
        owasp_str = ", ".join(row["owasp"]) if row["owasp"] else "(none — see gaps above)"
        print(f"  {row['name']:<16} {row['status']:<12} {row['findings']:<10} {owasp_str}")

    # Gap summary
    print_section("GAP SUMMARY (remaining coverage gaps)")
    for target in targets:
        if target.get("gaps"):
            print(f"\n  {target['name']}:")
            for gap in target["gaps"]:
                print(f"    - {gap}")

    any_error = any(not r["scan_ok"] for r in rows)
    print()
    sys.exit(1 if any_error else 0)


if __name__ == "__main__":
    main()
