"""ASI10 — Rogue Agents: unauthenticated agent creation, tool registration, and webhook injection."""
from __future__ import annotations

import re

from .base import BaseModule
from ..core.models import AgentSurface, Finding, OWASPCategory, Severity
from ..platforms.base import BasePlatform

_ROGUE_PATTERNS = [
    re.compile(r'(ignore|disregard|forget)\s+.{0,30}(instruction|above|previous|system|prompt)', re.I),
    re.compile(r'(your\s+new\s+task|new\s+instruction|override\s+previous)', re.I),
    re.compile(r'(reveal|output|print|show|repeat).{0,20}(system\s+prompt|instruction)', re.I),
    re.compile(r'exfiltrat[ei]', re.I),
    re.compile(r'send.{0,20}(to|webhook|http).{0,50}(api|endpoint|url)', re.I),
]

_FIELDS_TO_SCAN = [
    "systemMessage", "description", "prompt", "name",
    "system_message", "system_prompt", "instructions",
]


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
    "/api/v1/workflows",  # n8n
    "/assistants",        # LangGraph
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

# Qdrant: PUT /collections/{name} to create a new vector collection without auth
_QDRANT_COLLECTION_ENDPOINT = "/collections/condor-probe"
_QDRANT_COLLECTION_PAYLOAD  = {"vectors": {"size": 4, "distance": "Cosine"}}
# Chroma: POST /api/v2/collections (v1 deprecated → 410 Gone)
_CHROMA_COLLECTION_ENDPOINT = "/api/v2/tenants/default_tenant/databases/default_database/collections"
_CHROMA_COLLECTION_PAYLOAD  = {"name": "condor-probe"}

# Open WebUI: POST /api/v1/tools — tool registration with Python content
_OWI_TOOL_ENDPOINT = "/api/v1/tools"
_OWI_TOOL_PAYLOAD  = {
    "name": "condor-probe-tool",
    "description": "condor security probe",
    "content": "def main():\n    pass",
}


class RogueAgentsModule(BaseModule):
    name        = "rogue-agents"
    owasp_id    = OWASPCategory.ASI10
    description = "Detects unauthenticated agent creation, tool registration, and webhook injection (ASI10)"

    async def run(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(await self._check_unauthenticated_creation(surface, platform))
        findings.extend(await self._check_tool_registration(surface, platform))
        findings.extend(await self._check_webhook_registration(surface, platform))
        findings.extend(await self._check_vectorstore_creation(platform))
        findings.extend(await self._check_owui_tool_registration(platform))
        findings.extend(await self._check_existing_rogue_indicators(surface, platform))
        return findings

    async def _cleanup(self, platform: BasePlatform, endpoint: str, resource_id: str) -> Finding | None:
        """Attempt DELETE of a created test artifact; return an INFO finding if cleanup fails."""
        delete_path = f"{endpoint}/{resource_id}"
        try:
            dr = await platform.delete(delete_path)
            if dr.status_code not in (200, 204):
                return Finding(
                    title=f"Test artifact may persist: cleanup failed for {delete_path}",
                    severity=Severity.INFO,
                    owasp_id=self.owasp_id,
                    description=(
                        f"A test resource was created at {endpoint} but the cleanup DELETE "
                        f"to {delete_path} returned {dr.status_code}. The artifact may persist "
                        f"in the target system."
                    ),
                    evidence=f"DELETE {delete_path} → {dr.status_code}",
                    remediation="Manually remove the test artifact and verify DELETE auth is enforced.",
                    confidence=70,
                    endpoint=delete_path,
                )
        except Exception:
            return Finding(
                title=f"Test artifact may persist: cleanup failed for {delete_path}",
                severity=Severity.INFO,
                owasp_id=self.owasp_id,
                description=(
                    f"A test resource was created at {endpoint} but the cleanup DELETE "
                    f"to {delete_path} raised an exception. The artifact may persist."
                ),
                evidence=f"DELETE {delete_path} → exception during cleanup",
                remediation="Manually remove the test artifact.",
                confidence=60,
                endpoint=delete_path,
            )
        return None

    async def _check_unauthenticated_creation(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        """Check if new agents/flows can be created without authentication."""
        findings = []
        for endpoint in _CREATION_ENDPOINTS:
            created_id: str | None = None
            try:
                r = await platform.post(endpoint, json=_CREATION_PAYLOAD)
                if r.status_code in (200, 201) and _is_api_response(r):
                    try:
                        data = r.json()
                        created_id = (data.get("id") or data.get("assistant_id")) if isinstance(data, dict) else None
                    except Exception:
                        pass
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
                        cwe_id="CWE-306",
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
                        cwe_id="CWE-306",
                        endpoint=endpoint,
                    ))
            except Exception:
                pass
            finally:
                if created_id:
                    cleanup_finding = await self._cleanup(platform, endpoint, created_id)
                    if cleanup_finding:
                        findings.append(cleanup_finding)
        return findings

    async def _check_tool_registration(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        """Check if tools/plugins can be registered without authentication."""
        findings = []
        for endpoint in _TOOL_ENDPOINTS:
            created_id: str | None = None
            try:
                r = await platform.post(endpoint, json=_TOOL_PAYLOAD)
                if r.status_code in (200, 201) and _is_api_response(r):
                    try:
                        data = r.json()
                        created_id = data.get("id") if isinstance(data, dict) else None
                    except Exception:
                        pass
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
                        cwe_id="CWE-306",
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
                        cwe_id="CWE-306",
                        endpoint=endpoint,
                    ))
            except Exception:
                pass
            finally:
                if created_id:
                    cleanup_finding = await self._cleanup(platform, endpoint, created_id)
                    if cleanup_finding:
                        findings.append(cleanup_finding)
        return findings

    async def _check_webhook_registration(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        """Check if webhooks/triggers can be registered without authentication."""
        findings = []
        for endpoint in _WEBHOOK_ENDPOINTS:
            created_id: str | None = None
            try:
                r = await platform.post(endpoint, json=_WEBHOOK_PAYLOAD)
                if r.status_code in (200, 201) and _is_api_response(r):
                    try:
                        data = r.json()
                        created_id = data.get("id") if isinstance(data, dict) else None
                    except Exception:
                        pass
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
                        cwe_id="CWE-284",
                        endpoint=endpoint,
                    ))
            except Exception:
                pass
            finally:
                if created_id:
                    cleanup_finding = await self._cleanup(platform, endpoint, created_id)
                    if cleanup_finding:
                        findings.append(cleanup_finding)
        return findings

    async def _check_vectorstore_creation(self, platform: BasePlatform) -> list[Finding]:
        """Qdrant/Chroma: create vector collections without authentication."""
        findings: list[Finding] = []

        # Qdrant: PUT /collections/{name}
        _qdrant_probed = False
        try:
            r = await platform.put(_QDRANT_COLLECTION_ENDPOINT, json=_QDRANT_COLLECTION_PAYLOAD)
            if r.status_code not in (401, 403, 404) and _is_api_response(r):
                _qdrant_probed = True
                created = r.status_code in (200, 201)
                try:
                    data = r.json()
                    result = data.get("result") if isinstance(data, dict) else None
                    created = created or result is True
                except Exception:
                    pass
                if created or r.status_code in (400, 422):
                    findings.append(Finding(
                        title="Unauthenticated Qdrant collection creation accepted",
                        severity=Severity.CRITICAL if created else Severity.HIGH,
                        owasp_id=self.owasp_id,
                        description=(
                            "Qdrant's PUT /collections/{name} endpoint accepted a collection "
                            "creation request without authentication. "
                            + ("The collection was created. " if created else "Payload was rejected but auth was not enforced. ")
                            + "An attacker can create arbitrary collections to store poisoned "
                            "vectors that manipulate RAG pipelines consuming this Qdrant instance."
                        ),
                        evidence=f"PUT {_QDRANT_COLLECTION_ENDPOINT} → {r.status_code} (auth not enforced)",
                        remediation=(
                            "Enable Qdrant API key authentication "
                            "(QDRANT__SERVICE__API_KEY environment variable or --api-key flag)."
                        ),
                        confidence=90 if created else 70,
                        cwe_id="CWE-306",
                        endpoint=_QDRANT_COLLECTION_ENDPOINT,
                    ))
        except Exception:
            pass
        finally:
            if _qdrant_probed:
                try:
                    await platform.delete(_QDRANT_COLLECTION_ENDPOINT)
                except Exception:
                    pass

        # Chroma: POST /api/v2/.../collections
        _chroma_probed = False
        try:
            r = await platform.post(_CHROMA_COLLECTION_ENDPOINT, json=_CHROMA_COLLECTION_PAYLOAD)
            if r.status_code not in (401, 403, 404) and _is_api_response(r):
                _chroma_probed = True
                if r.status_code in (200, 201):
                    findings.append(Finding(
                        title="Unauthenticated Chroma collection creation accepted",
                        severity=Severity.CRITICAL,
                        owasp_id=self.owasp_id,
                        description=(
                            "Chroma's POST /api/v2/collections endpoint accepted a collection "
                            "creation request without authentication. An attacker can create "
                            "collections and insert poisoned vectors into RAG pipelines."
                        ),
                        evidence=f"POST {_CHROMA_COLLECTION_ENDPOINT} → {r.status_code} (collection created without auth)",
                        remediation=(
                            "Enable Chroma authentication "
                            "(CHROMA_SERVER_AUTHN_CREDENTIALS / CHROMA_SERVER_AUTHN_PROVIDER)."
                        ),
                        confidence=90,
                        cwe_id="CWE-306",
                        endpoint=_CHROMA_COLLECTION_ENDPOINT,
                    ))
                elif r.status_code in (400, 409, 422):
                    findings.append(Finding(
                        title="Chroma collection creation endpoint accessible without authentication",
                        severity=Severity.HIGH,
                        owasp_id=self.owasp_id,
                        description=(
                            f"Chroma's {_CHROMA_COLLECTION_ENDPOINT} endpoint responded to an "
                            f"unauthenticated POST (HTTP {r.status_code}). A correctly formatted "
                            "payload may succeed in creating a collection."
                        ),
                        evidence=f"POST {_CHROMA_COLLECTION_ENDPOINT} → {r.status_code} (auth not enforced)",
                        remediation="Enable Chroma authentication.",
                        confidence=70,
                        cwe_id="CWE-306",
                        endpoint=_CHROMA_COLLECTION_ENDPOINT,
                    ))
        except Exception:
            pass
        finally:
            if _chroma_probed:
                try:
                    await platform.delete(f"{_CHROMA_COLLECTION_ENDPOINT}/condor-probe")
                except Exception:
                    pass

        return findings

    async def _check_owui_tool_registration(self, platform: BasePlatform) -> list[Finding]:
        """Open WebUI: register a tool (Python content) without authentication."""
        findings: list[Finding] = []
        created_id: str | None = None
        try:
            r = await platform.post(_OWI_TOOL_ENDPOINT, json=_OWI_TOOL_PAYLOAD)
            if r.status_code in (401, 403, 404):
                return findings
            if not _is_api_response(r):
                return findings
            if r.status_code in (200, 201):
                try:
                    data = r.json()
                    created_id = data.get("id") if isinstance(data, dict) else None
                except Exception:
                    pass
                findings.append(Finding(
                    title="Unauthenticated Open WebUI tool registration accepted",
                    severity=Severity.CRITICAL,
                    owasp_id=self.owasp_id,
                    description=(
                        "Open WebUI's /api/v1/tools endpoint accepted a tool registration "
                        "containing Python code without authentication. Tools are executed "
                        "server-side when invoked by the LLM, enabling persistent RCE "
                        "disguised as a legitimate tool in the tool registry."
                    ),
                    evidence=f"POST {_OWI_TOOL_ENDPOINT} → {r.status_code} (tool registered without auth)",
                    remediation=(
                        "Enable Open WebUI authentication (WEBUI_AUTH=True). "
                        "Restrict tool registration to admin users only."
                    ),
                    confidence=92,
                    cwe_id="CWE-306",
                    endpoint=_OWI_TOOL_ENDPOINT,
                ))
            elif r.status_code in (400, 422):
                findings.append(Finding(
                    title="Open WebUI tool registration endpoint accessible without authentication",
                    severity=Severity.HIGH,
                    owasp_id=self.owasp_id,
                    description=(
                        f"Open WebUI's {_OWI_TOOL_ENDPOINT} endpoint responded to an unauthenticated "
                        f"POST (HTTP {r.status_code}). A correctly formatted Python tool payload "
                        "may achieve persistent code execution."
                    ),
                    evidence=f"POST {_OWI_TOOL_ENDPOINT} → {r.status_code} (auth not enforced)",
                    remediation="Enable Open WebUI authentication. Restrict tool registration to admin users.",
                    confidence=70,
                    cwe_id="CWE-306",
                    endpoint=_OWI_TOOL_ENDPOINT,
                ))
        except Exception:
            pass
        finally:
            if created_id:
                try:
                    await platform.delete(f"{_OWI_TOOL_ENDPOINT}/{created_id}")
                except Exception:
                    pass
        return findings

    async def _check_existing_rogue_indicators(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        """Scan already-registered flows and tools for injection patterns in system prompts/descriptions."""
        findings = []
        resources: list[tuple[str, str, dict]] = []

        for flow in surface.flows:
            if isinstance(flow, dict):
                resources.append(("flow", flow.get("name", "unknown"), flow))
        for tool in surface.tools:
            if isinstance(tool, dict):
                resources.append(("tool", tool.get("name", "unknown"), tool))

        for endpoint in _CREATION_ENDPOINTS:
            try:
                r = await platform.get(endpoint)
                if r.status_code == 200 and _is_api_response(r):
                    data = r.json()
                    items = data if isinstance(data, list) else data.get("data", []) if isinstance(data, dict) else []
                    for item in items:
                        if isinstance(item, dict):
                            resources.append(("resource", item.get("name", "unknown"), item))
            except Exception:
                pass

        seen: set[tuple] = set()
        for resource_type, resource_name, resource_data in resources:
            for field in _FIELDS_TO_SCAN:
                value = resource_data.get(field, "")
                if not isinstance(value, str) or not value:
                    continue
                for pattern in _ROGUE_PATTERNS:
                    m = pattern.search(value)
                    if m:
                        resource_id = resource_data.get("id", resource_name)
                        key = (resource_type, resource_id, field)
                        if key in seen:
                            break
                        seen.add(key)
                        start = max(0, m.start() - 20)
                        snippet = value[start:m.end() + 20].strip()
                        findings.append(Finding(
                            title=(
                                f"Existing Rogue Agent Detected: Suspicious Prompt "
                                f"in {resource_type} '{resource_name}'"
                            ),
                            severity=Severity.HIGH,
                            owasp_id=self.owasp_id,
                            description=(
                                f"An existing {resource_type} named '{resource_name}' contains a "
                                f"suspicious injection pattern in its '{field}' field. This may indicate "
                                f"the agent has been compromised or misconfigured with a malicious prompt."
                            ),
                            evidence=f"Field '{field}': ...{snippet}...",
                            remediation=(
                                "Review and sanitize all agent/tool system prompts and descriptions. "
                                "Implement approval workflows and audit logging for prompt changes."
                            ),
                            confidence=80,
                            cwe_id="CWE-306",
                            endpoint="",
                        ))
                        break
        return findings
