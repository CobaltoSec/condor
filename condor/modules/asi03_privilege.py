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
    # Ollama
    ("/api/tags",            Severity.MEDIUM,   "installed model inventory"),
    ("/api/ps",              Severity.LOW,      "running model process list"),
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


# Flowise 3.x header bypass (CVE-2026-30820, patched in 3.0.13)
# Middleware in packages/server/src/index.ts short-circuits auth on this header.
_BYPASS_HEADER = {"x-request-from": "internal"}
_BYPASS_ENDPOINTS = [
    ("/api/v1/apikey",       Severity.CRITICAL, "platform API keys"),
    ("/api/v1/credentials",  Severity.CRITICAL, "stored credentials"),
    ("/api/v1/chatflows",    Severity.HIGH,     "agent workflows"),
    ("/api/v1/variables",    Severity.HIGH,     "environment variables"),
    ("/api/v1/tools",        Severity.MEDIUM,   "tool configurations"),
]

_IDOR_ENDPOINTS = [
    "/api/v1/chatflows/1",
    "/api/v1/chatflows/2",
    "/api/v1/chatflows/3",
    "/api/v1/chatflows/4",
    "/api/v1/chatflows/5",
    "/api/v1/chatflows/00000000-0000-0000-0000-000000000001",
]

_MASS_ASSIGN_FIELDS = {
    "role": "admin",
    "isAdmin": True,
    "permissions": ["admin", "write", "delete"],
    "userType": "administrator",
}


class PrivilegeAbuseModule(BaseModule):
    name        = "privilege-abuse"
    owasp_id    = OWASPCategory.ASI03
    description = "Detects unauthenticated access to sensitive platform endpoints (ASI03)"

    async def _check_idor(self, platform: BasePlatform) -> list[Finding]:
        for endpoint in _IDOR_ENDPOINTS:
            try:
                r = await platform.get(endpoint)
                if r.status_code == 200 and _is_api_response(r):
                    snippet = r.text[:200] if r.text else "(no body)"
                    return [Finding(
                        title="IDOR: Unauthenticated Object Access",
                        severity=Severity.MEDIUM,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The endpoint {endpoint} returns object data without authentication "
                            f"and without validating the caller's ownership. An attacker can "
                            f"enumerate sequential IDs to access other users' data."
                        ),
                        evidence=f"GET {endpoint} → 200 OK without auth: {snippet}",
                        remediation=(
                            "Enforce object-level authorization: verify the authenticated user "
                            "owns or has explicit access to the requested resource ID."
                        ),
                        confidence=85,
                        cwe_id="CWE-639",
                        endpoint=endpoint,
                    )]
            except Exception:
                pass
        return []

    async def _check_header_bypass(self, platform: BasePlatform) -> list[Finding]:
        findings: list[Finding] = []
        for endpoint, severity, what in _BYPASS_ENDPOINTS:
            try:
                r_base = await platform.get(endpoint)
                if r_base.status_code not in (401, 403):
                    continue  # Not auth-gated — covered by main read probe

                r_bypass = await platform.get(endpoint, headers=_BYPASS_HEADER)
                if r_bypass.status_code == 200 and _is_api_response(r_bypass):
                    findings.append(Finding(
                        title=f"Auth bypass via x-request-from:internal: {endpoint}",
                        severity=severity,
                        owasp_id=self.owasp_id,
                        description=(
                            f"Flowise endpoint {endpoint} bypasses authentication when the "
                            f"'x-request-from: internal' header is present, exposing {what}. "
                            f"Any unauthenticated attacker can spoof this header to access "
                            f"protected data. (CVE-2026-30820, affects Flowise ≤ 3.0.12)"
                        ),
                        evidence=(
                            f"GET {endpoint} → {r_base.status_code} (auth required). "
                            f"GET {endpoint} + x-request-from:internal → 200 OK (bypassed)"
                        ),
                        remediation="Update Flowise to 3.0.13+, which validates the x-request-from header server-side.",
                        confidence=98,
                        cwe_id="CWE-285",
                        endpoint=endpoint,
                    ))
            except Exception:
                pass
        return findings

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
                        cwe_id="CWE-306",
                        endpoint=endpoint,
                    ))
            except Exception:
                pass

        # Write access + mass assignment probe
        for method, endpoint, severity, what in _WRITE_ENDPOINTS:
            try:
                payload = {"name": "_condor_probe_", "test": True, **_MASS_ASSIGN_FIELDS}
                r = await platform.post(endpoint, json=payload)
                if r.status_code in (200, 201) and _is_api_response(r):
                    # Try to clean up created resource
                    try:
                        body = r.json()
                        item_id = body.get("id") or body.get("_id")
                        if item_id:
                            await platform.delete(f"{endpoint}/{item_id}")
                    except Exception:
                        body = {}

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
                        cwe_id="CWE-306",
                        endpoint=endpoint,
                    ))

                    # Check mass assignment: did any privilege field survive into the response?
                    try:
                        resp_body = r.json() if not isinstance(body, dict) else body  # type: ignore[assignment]
                    except Exception:
                        resp_body = {}
                    accepted = [
                        f"{k}={v!r}" for k, v in _MASS_ASSIGN_FIELDS.items()
                        if resp_body.get(k) == v
                    ]
                    if accepted:
                        findings.append(Finding(
                            title=f"Mass Assignment: Privilege Fields Accepted at {endpoint}",
                            severity=Severity.MEDIUM,
                            owasp_id=self.owasp_id,
                            description=(
                                f"The endpoint {endpoint} accepted and stored privilege-escalation "
                                f"fields submitted in the POST body. An attacker can craft requests "
                                f"to assign admin roles or bypass access controls."
                            ),
                            evidence=f"POST {endpoint} → accepted fields: {', '.join(accepted)}",
                            remediation=(
                                "Use an explicit allowlist of fields that clients are permitted to set. "
                                "Strip or reject any fields not in the allowlist before persistence."
                            ),
                            confidence=90,
                            cwe_id="CWE-915",
                            endpoint=endpoint,
                        ))
            except Exception:
                pass

        findings.extend(await self._check_idor(platform))
        findings.extend(await self._check_header_bypass(platform))
        return findings
