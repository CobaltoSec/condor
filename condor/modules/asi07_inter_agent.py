"""ASI07 — Insecure Inter-Agent Communication: exposed sub-agent channels and unauthenticated spawning."""
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

# Flowise multi-agent flow enumeration
_FLOWISE_AGENTFLOW_ENDPOINTS = [
    "/api/v1/agentflows",
    "/api/v1/agentflow",
]
# Internal agent-to-agent communication channel (higher privilege than /prediction)
_FLOWISE_INTERNAL_PREDICTION = "/api/v1/internal-prediction/{flow_id}"

# Headers that simulate an internal/trusted agent origin
_FORGED_INTERNAL_HEADERS = {
    "X-Forwarded-For": "127.0.0.1",
    "X-Internal-Request": "true",
    "X-Agent-Source": "internal",
    "X-Flowise-Internal": "1",
}

# AutoGen Studio inter-agent endpoints
_AUTOGEN_INTERAGENT_ENDPOINTS = [
    "/api/teams",
    "/api/v1/teams",
    "/api/sessions",
    "/api/v1/sessions",
    "/api/runs",
    "/api/v1/runs",
]
_AUTOGEN_RUN_PAYLOAD = {
    "task": "condor-security-probe",
    "team_id": "condor-probe",
}

# Dify multi-agent workflow trigger
_DIFY_WORKFLOW_ENDPOINTS = [
    "/v1/workflows/run",
]
_DIFY_WORKFLOW_PAYLOAD = {
    "inputs": {},
    "response_mode": "blocking",
    "user": "condor-probe",
}


class InterAgentModule(BaseModule):
    name        = "inter-agent"
    owasp_id    = OWASPCategory.ASI07
    description = "Detects exposed inter-agent communication channels and unauthenticated agent spawning (ASI07)"

    async def run(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(await self._check_agentflows(surface, platform))
        findings.extend(await self._check_internal_prediction(surface, platform))
        findings.extend(await self._check_origin_forgery(surface, platform))
        findings.extend(await self._check_autogen_teams(surface, platform))
        findings.extend(await self._check_workflow_trigger(surface, platform))
        return findings

    async def _check_agentflows(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        """Flowise: enumerate multi-agent flows without auth."""
        findings = []
        for endpoint in _FLOWISE_AGENTFLOW_ENDPOINTS:
            try:
                r = await platform.get(endpoint)
                if r.status_code == 200 and _is_api_response(r):
                    try:
                        data = r.json()
                        count = len(data) if isinstance(data, list) else 0
                    except Exception:
                        count = 0
                    findings.append(Finding(
                        title=f"Unauthenticated multi-agent flow enumeration: {endpoint}",
                        severity=Severity.HIGH,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The Flowise endpoint {endpoint} exposes multi-agent flow definitions "
                            f"without authentication. An attacker can enumerate agent architectures, "
                            f"discover inter-agent communication patterns, and identify injection "
                            f"points for cross-agent privilege escalation."
                        ),
                        evidence=(
                            f"GET {endpoint} → 200 OK"
                            + (f" ({count} agent flows exposed)" if count else "")
                        ),
                        remediation=(
                            "Enable Flowise authentication. Restrict agentflow endpoints "
                            "to authenticated users."
                        ),
                        confidence=90,
                        cwe_id="CWE-306",
                        endpoint=endpoint,
                    ))
            except Exception:
                pass
        return findings

    async def _check_internal_prediction(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        """Flowise: probe internal-prediction endpoint (agent-to-agent channel, bypasses outer guardrails)."""
        findings = []
        flow_ids = [f.get("id") for f in surface.flows if isinstance(f, dict) and f.get("id")]
        if not flow_ids:
            return findings
        for flow_id in flow_ids[:3]:
            endpoint = _FLOWISE_INTERNAL_PREDICTION.format(flow_id=flow_id)
            try:
                r = await platform.post(endpoint, json={"question": "condor-probe"})
                if r.status_code in (200, 201) and _is_api_response(r):
                    findings.append(Finding(
                        title=f"Internal agent prediction channel exposed: {endpoint}",
                        severity=Severity.CRITICAL,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The Flowise internal prediction endpoint {endpoint} accepts requests "
                            f"without authentication. This channel is designed for agent-to-agent "
                            f"communication and bypasses outer-layer prompt guardrails. An attacker "
                            f"can inject arbitrary messages directly into the agent chain."
                        ),
                        evidence=f"POST {endpoint} → {r.status_code} (internal channel accessible externally)",
                        remediation=(
                            "Enable Flowise authentication. Restrict internal-prediction endpoints "
                            "to loopback/internal network via reverse proxy."
                        ),
                        confidence=95,
                        cwe_id="CWE-306",
                        endpoint=endpoint,
                    ))
                    break
            except Exception:
                pass
        return findings

    async def _check_origin_forgery(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        """Flowise: test whether forged internal-origin headers bypass inter-agent channel auth."""
        findings = []
        flow_ids = [f.get("id") for f in surface.flows if isinstance(f, dict) and f.get("id")]
        if not flow_ids:
            return findings
        for flow_id in flow_ids[:2]:
            endpoint = _FLOWISE_INTERNAL_PREDICTION.format(flow_id=flow_id)
            try:
                r_base = await platform.post(endpoint, json={"question": "condor-probe"})
                if r_base.status_code not in (401, 403):
                    continue  # already open or unavailable — _check_internal_prediction covers open case
                r_forged = await platform.post(
                    endpoint,
                    json={"question": "condor-probe"},
                    headers=_FORGED_INTERNAL_HEADERS,
                )
                if r_forged.status_code in (200, 201) and _is_api_response(r_forged):
                    findings.append(Finding(
                        title=f"Inter-Agent Channel: Origin Header Forgery Accepted: {endpoint}",
                        severity=Severity.HIGH,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The Flowise internal prediction endpoint {endpoint} rejected unauthenticated "
                            f"requests ({r_base.status_code}) but accepted a request with forged "
                            f"internal-origin headers (X-Forwarded-For: 127.0.0.1, X-Internal-Request: true). "
                            f"An attacker can bypass inter-agent channel authentication by spoofing these headers."
                        ),
                        evidence=(
                            f"POST {endpoint} without headers → {r_base.status_code}; "
                            f"POST with X-Internal-Request: true → {r_forged.status_code} (access granted)"
                        ),
                        remediation=(
                            "Do not trust X-Forwarded-For or custom internal-origin headers for access control. "
                            "Restrict internal-prediction endpoints to loopback only via reverse proxy firewall rules."
                        ),
                        confidence=90,
                        cwe_id="CWE-346",
                        endpoint=endpoint,
                    ))
                    break
            except Exception:
                pass
        return findings

    async def _check_autogen_teams(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        """AutoGen Studio: unauthenticated access to team/session/run endpoints."""
        findings = []
        for endpoint in _AUTOGEN_INTERAGENT_ENDPOINTS:
            try:
                r = await platform.get(endpoint)
                if r.status_code == 200 and _is_api_response(r):
                    try:
                        data = r.json()
                        items = data.get("data", data) if isinstance(data, dict) else data
                        count = len(items) if isinstance(items, list) else 0
                    except Exception:
                        count = 0
                    findings.append(Finding(
                        title=f"Unauthenticated AutoGen inter-agent endpoint: {endpoint}",
                        severity=Severity.HIGH,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The AutoGen Studio endpoint {endpoint} is accessible without "
                            f"authentication. Exposed team and session endpoints allow an attacker "
                            f"to enumerate agent teams, hijack active runs, or inject tasks "
                            f"into the inter-agent message chain."
                        ),
                        evidence=(
                            f"GET {endpoint} → 200 OK"
                            + (f" ({count} records exposed)" if count else "")
                        ),
                        remediation=(
                            "Enable AutoGen Studio authentication. Use a reverse proxy with "
                            "authentication in front of the AutoGen Studio API."
                        ),
                        confidence=85,
                        cwe_id="CWE-306",
                        endpoint=endpoint,
                    ))
            except Exception:
                pass
        return findings

    async def _check_workflow_trigger(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        """Dify: unauthenticated multi-agent workflow execution trigger."""
        findings = []
        for endpoint in _DIFY_WORKFLOW_ENDPOINTS:
            try:
                r = await platform.post(endpoint, json=_DIFY_WORKFLOW_PAYLOAD)
                if r.status_code in (200, 201, 202) and _is_api_response(r):
                    findings.append(Finding(
                        title=f"Unauthenticated workflow execution trigger: {endpoint}",
                        severity=Severity.CRITICAL,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The Dify endpoint {endpoint} triggers multi-agent workflow execution "
                            f"without authentication. An attacker can spawn agents, consume "
                            f"resources, and inject payloads into the inter-agent message chain."
                        ),
                        evidence=f"POST {endpoint} → {r.status_code} (workflow trigger accepted without auth)",
                        remediation=(
                            "Require a valid API key for Dify workflow endpoints. "
                            "Implement rate limiting and input validation on workflow triggers."
                        ),
                        confidence=85,
                        cwe_id="CWE-306",
                        endpoint=endpoint,
                    ))
                elif r.status_code in (400, 422) and _is_api_response(r):
                    findings.append(Finding(
                        title=f"Workflow trigger endpoint accessible without auth: {endpoint}",
                        severity=Severity.MEDIUM,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The Dify endpoint {endpoint} is reachable without authentication "
                            f"(returned {r.status_code} for probe payload). A correctly formatted "
                            f"request may trigger multi-agent workflow execution."
                        ),
                        evidence=f"POST {endpoint} → {r.status_code} (auth not enforced)",
                        remediation=(
                            "Require a valid API key for Dify workflow endpoints."
                        ),
                        confidence=65,
                        cwe_id="CWE-306",
                        endpoint=endpoint,
                    ))
            except Exception:
                pass
        return findings
