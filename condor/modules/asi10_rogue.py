"""ASI10 — Rogue Agents: unauthenticated agent creation, tool registration, and webhook injection."""
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


_CREATION_ENDPOINTS = [
    "/api/v1/chatflows",
    "/api/v1/flows",
    "/console/api/apps",
    "/api/agents",
]

_TOOL_ENDPOINTS = [
    "/api/v1/tools",
    "/api/v1/custom_components",
    "/api/v1/plugins",
]

_WEBHOOK_ENDPOINTS = [
    "/api/v1/webhooks",
    "/api/v1/triggers",
    "/api/v1/integrations",
]

_CREATION_PAYLOAD  = {"name": "condor-probe"}
_TOOL_PAYLOAD      = {"name": "condor-probe-tool", "func": "print"}
_WEBHOOK_PAYLOAD   = {"url": "http://condor.probe/callback", "events": ["run.completed"]}


class RogueAgentsModule(BaseModule):
    name        = "rogue-agents"
    owasp_id    = OWASPCategory.ASI10
    description = "Detects unauthenticated agent creation, tool registration, and webhook injection (ASI10)"

    async def run(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(await self._check_unauthenticated_creation(surface, platform))
        findings.extend(await self._check_tool_registration(surface, platform))
        findings.extend(await self._check_webhook_registration(surface, platform))
        return findings

    async def _check_unauthenticated_creation(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        """Check if new agents/flows can be created without authentication."""
        findings = []
        for endpoint in _CREATION_ENDPOINTS:
            try:
                r = await platform.post(endpoint, json=_CREATION_PAYLOAD)
                if r.status_code in (200, 201) and _is_api_response(r):
                    findings.append(Finding(
                        title=f"Unauthenticated agent creation accepted: {endpoint}",
                        severity=Severity.CRITICAL,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The endpoint {endpoint} accepted agent creation without authentication. "
                            f"An attacker can spawn rogue agents with arbitrary system prompts and tool "
                            f"access, enabling unauthorized autonomous actions, data exfiltration, and "
                            f"persistent access within the agentic platform."
                        ),
                        evidence=f"POST {endpoint} → {r.status_code} (agent created without auth)",
                        remediation=(
                            "Require authentication and authorization for all agent creation endpoints. "
                            "Implement approval workflows for new agent deployments."
                        ),
                        confidence=90,
                        endpoint=endpoint,
                    ))
                elif r.status_code in (400, 422) and _is_api_response(r):
                    findings.append(Finding(
                        title=f"Agent creation endpoint accessible without auth: {endpoint}",
                        severity=Severity.HIGH,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The agent creation endpoint {endpoint} is reachable without authentication "
                            f"(returned {r.status_code} for probe payload). A correctly formatted "
                            f"request may create a rogue agent with arbitrary capabilities."
                        ),
                        evidence=f"POST {endpoint} → {r.status_code} (auth not enforced, payload rejected)",
                        remediation=(
                            "Require authentication for all agent creation endpoints. "
                            "Return 401 Unauthorized before processing any request body."
                        ),
                        confidence=75,
                        endpoint=endpoint,
                    ))
            except Exception:
                pass
        return findings

    async def _check_tool_registration(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        """Check if tools/plugins can be registered without authentication."""
        findings = []
        for endpoint in _TOOL_ENDPOINTS:
            try:
                r = await platform.post(endpoint, json=_TOOL_PAYLOAD)
                if r.status_code in (200, 201) and _is_api_response(r):
                    findings.append(Finding(
                        title=f"Unauthenticated tool registration accepted: {endpoint}",
                        severity=Severity.CRITICAL,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The endpoint {endpoint} accepted tool/plugin registration without "
                            f"authentication. An attacker can register malicious tools that execute "
                            f"arbitrary code, exfiltrate data, or pivot to other systems when invoked "
                            f"by legitimate agents."
                        ),
                        evidence=f"POST {endpoint} → {r.status_code} (tool registered without auth)",
                        remediation=(
                            "Require authentication and code review for all tool/plugin registrations. "
                            "Implement a tool allowlist and sign approved tools."
                        ),
                        confidence=88,
                        endpoint=endpoint,
                    ))
                elif r.status_code in (400, 422) and _is_api_response(r):
                    findings.append(Finding(
                        title=f"Tool registration endpoint accessible without auth: {endpoint}",
                        severity=Severity.HIGH,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The tool registration endpoint {endpoint} is reachable without "
                            f"authentication (returned {r.status_code} for probe payload). "
                            f"A correctly formatted request may register a malicious tool."
                        ),
                        evidence=f"POST {endpoint} → {r.status_code} (auth not enforced, payload rejected)",
                        remediation=(
                            "Require authentication for tool/plugin registration endpoints."
                        ),
                        confidence=70,
                        endpoint=endpoint,
                    ))
            except Exception:
                pass
        return findings

    async def _check_webhook_registration(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        """Check if webhooks/triggers can be registered without authentication."""
        findings = []
        for endpoint in _WEBHOOK_ENDPOINTS:
            try:
                r = await platform.post(endpoint, json=_WEBHOOK_PAYLOAD)
                if r.status_code in (200, 201) and _is_api_response(r):
                    findings.append(Finding(
                        title=f"Unauthenticated webhook registration accepted: {endpoint}",
                        severity=Severity.HIGH,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The endpoint {endpoint} accepted webhook/trigger registration without "
                            f"authentication. An attacker can register a callback URL to receive agent "
                            f"events, enabling data exfiltration and unauthorized automation in response "
                            f"to agent state transitions."
                        ),
                        evidence=f"POST {endpoint} → {r.status_code} (webhook registered without auth)",
                        remediation=(
                            "Require authentication for webhook/trigger registration. "
                            "Validate callback URLs against an allowlist. "
                            "Implement webhook signing to prevent forged events."
                        ),
                        confidence=85,
                        endpoint=endpoint,
                    ))
            except Exception:
                pass
        return findings
