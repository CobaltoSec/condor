"""ASI03 — Agent Identity & Privilege Abuse: unauthenticated access to sensitive endpoints."""
from __future__ import annotations

from .base import BaseModule
from ..core.models import AgentSurface, Finding, OWASPCategory, Severity
from ..platforms.base import BasePlatform


def _is_api_response(r) -> bool:
    """Return False if response is HTML (SPA catch-all), True for JSON/API responses."""
    try:
        ct = r.headers.get("content-type", "")
        if isinstance(ct, str):
            return "text/html" not in ct
    except Exception:
        pass
    return True

# (endpoint, severity, what it exposes)
_SENSITIVE = [
    ("/api/v1/credentials",  Severity.CRITICAL, "stored credentials and API keys"),
    ("/api/v1/apikey",       Severity.CRITICAL, "platform API keys"),
    ("/api/v1/variables",    Severity.HIGH,     "environment variables and config"),
    ("/api/v1/chatflows",    Severity.HIGH,     "all agent workflows"),
    ("/api/v1/tools",        Severity.MEDIUM,   "tool definitions and configurations"),
    ("/v1/workspaces",       Severity.HIGH,     "Dify workspace data"),
    ("/studio/api/teams",    Severity.HIGH,     "AutoGen Studio team data"),
    ("/api/v1/flows",        Severity.HIGH,     "Langflow flow definitions"),
]

# Endpoints that allow unauthenticated writes (worse than reads)
_WRITE_ENDPOINTS = [
    ("POST", "/api/v1/chatflows",  Severity.CRITICAL, "create arbitrary workflows"),
    ("POST", "/api/v1/tools",      Severity.CRITICAL, "create arbitrary tools"),
    ("POST", "/api/v1/variables",  Severity.HIGH,     "inject environment variables"),
]


class PrivilegeAbuseModule(BaseModule):
    name        = "privilege-abuse"
    owasp_id    = OWASPCategory.ASI03
    description = "Detects unauthenticated access to sensitive platform endpoints (ASI03)"

    async def run(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        findings: list[Finding] = []

        # Read access
        for endpoint, severity, what in _SENSITIVE:
            try:
                r = await platform.get(endpoint)
                if r.status_code == 200 and _is_api_response(r):
                    try:
                        body = r.json()
                        count = len(body) if isinstance(body, list) else 1
                        evidence = f"GET {endpoint} → 200 OK ({count} item(s) returned without auth)"
                    except Exception:
                        evidence = f"GET {endpoint} → 200 OK (non-JSON response, {len(r.content)} bytes)"

                    findings.append(Finding(
                        title=f"Unauthenticated read access to {endpoint}",
                        severity=severity,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The endpoint {endpoint} returns {what} without requiring "
                            f"authentication. An unauthenticated attacker can enumerate "
                            f"and exfiltrate sensitive configuration data."
                        ),
                        evidence=evidence,
                        remediation=(
                            "Enable authentication in the platform settings. "
                            "For Flowise: set FLOWISE_USERNAME and FLOWISE_PASSWORD env vars. "
                            "For Dify: ensure the API requires a valid Bearer token."
                        ),
                        confidence=95,
                        endpoint=endpoint,
                    ))
            except Exception:
                pass

        # Write access
        for method, endpoint, severity, what in _WRITE_ENDPOINTS:
            try:
                r = await platform.post(endpoint, json={"name": "_condor_probe_", "test": True})
                if r.status_code in (200, 201) and _is_api_response(r):
                    # Try to clean up
                    try:
                        body = r.json()
                        item_id = body.get("id") or body.get("_id")
                        if item_id:
                            await platform.delete(f"{endpoint}/{item_id}")
                    except Exception:
                        pass

                    findings.append(Finding(
                        title=f"Unauthenticated write access to {endpoint}",
                        severity=severity,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The endpoint {endpoint} allows unauthenticated POST requests "
                            f"to {what}. An attacker can inject malicious workflows or tools "
                            f"that execute in the context of legitimate users."
                        ),
                        evidence=f"POST {endpoint} → {r.status_code} (created without auth)",
                        remediation="Enable platform authentication and enforce authorization on all write endpoints.",
                        confidence=98,
                        endpoint=endpoint,
                    ))
            except Exception:
                pass

        return findings
