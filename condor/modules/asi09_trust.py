"""ASI09 — Human-Agent Trust Exploitation: system prompt exposure and unauthenticated identity modification."""
from __future__ import annotations
import re

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


_HUMAN_IMPERSONATION_RE = re.compile(
    r"i am a human|i'm a person|you are talking to a real|not an ai|i am not an ai",
    re.IGNORECASE,
)

_SYSTEM_PROMPT_FIELDS = ("systemMessage", "systemPrompt", "system_prompt", "system_message")

_DEFINITION_TEMPLATES = [
    "/api/v1/chatflows/{flow_id}",
    "/api/v1/flows/{flow_id}",
    "/console/api/apps/{flow_id}",
    "/api/agents/{flow_id}",
]

_PUT_TEMPLATES = [
    "/api/v1/chatflows/{flow_id}",
    "/api/v1/flows/{flow_id}",
]

_PROBE_PAYLOAD = {"systemMessage": "condor-probe"}


def _extract_system_prompt(data: dict) -> str | None:
    """Extract system prompt value from common top-level and nested locations."""
    for field in _SYSTEM_PROMPT_FIELDS:
        val = data.get(field)
        if val and isinstance(val, str):
            return val
    for wrapper in ("config", "modelConfig", "chatbotConfig", "details"):
        nested = data.get(wrapper)
        if isinstance(nested, dict):
            for field in _SYSTEM_PROMPT_FIELDS:
                val = nested.get(field)
                if val and isinstance(val, str):
                    return val
    return None


def _has_system_prompt_field(text: str) -> bool:
    text_lower = text.lower()
    return any(f.lower() in text_lower for f in _SYSTEM_PROMPT_FIELDS)


class TrustExploitationModule(BaseModule):
    name        = "trust-exploitation"
    owasp_id    = OWASPCategory.ASI09
    description = "Detects system prompt exposure and unauthenticated agent identity modification (ASI09)"

    async def run(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(await self._check_system_prompt_exposure(surface, platform))
        findings.extend(await self._check_system_prompt_modification(surface, platform))
        return findings

    async def _check_system_prompt_exposure(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        """Check if agent definitions exposing system prompts are accessible without auth."""
        findings = []
        flow_ids = [f.get("id") for f in surface.flows if isinstance(f, dict) and f.get("id")]
        if not flow_ids:
            return findings

        for flow_id in flow_ids[:3]:
            for template in _DEFINITION_TEMPLATES:
                endpoint = template.format(flow_id=flow_id)
                try:
                    r = await platform.get(endpoint)
                    if r.status_code != 200 or not _is_api_response(r):
                        continue
                    if not _has_system_prompt_field(r.text):
                        continue

                    system_prompt: str | None = None
                    try:
                        data = r.json()
                        system_prompt = _extract_system_prompt(data)
                    except Exception:
                        pass

                    is_impersonation = (
                        system_prompt is not None
                        and bool(_HUMAN_IMPERSONATION_RE.search(system_prompt))
                    )

                    if is_impersonation:
                        findings.append(Finding(
                            title=f"System prompt contains human impersonation claim: {endpoint}",
                            severity=Severity.CRITICAL,
                            owasp_id=self.owasp_id,
                            description=(
                                f"The agent definition at {endpoint} is accessible without authentication "
                                f"and its system prompt contains language that impersonates a human. "
                                f"This deceives users into believing they are speaking with a real person, "
                                f"enabling social engineering, fraud, and erosion of human-agent trust boundaries."
                            ),
                            evidence=(
                                f"GET {endpoint} → 200 OK; system prompt contains human impersonation: "
                                f'"{system_prompt[:120]}"'
                            ),
                            remediation=(
                                "Remove human impersonation language from agent system prompts. "
                                "Agents must disclose their AI nature. "
                                "Restrict agent definition endpoints to authenticated users."
                            ),
                            confidence=90,
                            endpoint=endpoint,
                        ))
                    else:
                        findings.append(Finding(
                            title=f"Unauthenticated system prompt exposure: {endpoint}",
                            severity=Severity.HIGH,
                            owasp_id=self.owasp_id,
                            description=(
                                f"The agent definition at {endpoint} exposes system prompt fields "
                                f"without authentication. Leaked system prompts reveal proprietary "
                                f"instructions, persona details, and constraints, enabling targeted "
                                f"jailbreak attempts and trust manipulation attacks."
                            ),
                            evidence=f"GET {endpoint} → 200 OK; system prompt field exposed in response",
                            remediation=(
                                "Restrict agent definition endpoints to authenticated users. "
                                "Avoid returning system prompt content in unauthenticated API responses."
                            ),
                            confidence=85,
                            endpoint=endpoint,
                        ))
                    return findings
                except Exception:
                    pass
        return findings

    async def _check_system_prompt_modification(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        """Check if system prompt can be overwritten via unauthenticated PUT."""
        findings = []
        flow_ids = [f.get("id") for f in surface.flows if isinstance(f, dict) and f.get("id")]
        if not flow_ids:
            return findings

        for flow_id in flow_ids[:2]:
            for template in _PUT_TEMPLATES:
                endpoint = template.format(flow_id=flow_id)
                try:
                    r = await platform.put(endpoint, json=_PROBE_PAYLOAD)
                    if r.status_code in (200, 201) and _is_api_response(r):
                        findings.append(Finding(
                            title=f"Unauthenticated system prompt modification accepted: {endpoint}",
                            severity=Severity.CRITICAL,
                            owasp_id=self.owasp_id,
                            description=(
                                f"The endpoint {endpoint} accepted a PUT request modifying the agent "
                                f"system prompt without authentication. An attacker can reprogram the "
                                f"agent's identity and instructions to impersonate a human, manipulate "
                                f"users, and completely compromise human-agent trust boundaries."
                            ),
                            evidence=f"PUT {endpoint} → {r.status_code} (system prompt modification accepted without auth)",
                            remediation=(
                                "Require authentication and authorization for all PUT/PATCH operations "
                                "on agent definitions. Implement audit logging for system prompt changes."
                            ),
                            confidence=90,
                            endpoint=endpoint,
                        ))
                        return findings
                except Exception:
                    pass
        return findings
