"""ASI06 — Memory & Context Poisoning: unauthenticated vectorstore access and document injection."""
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

# Flowise document store
_FLOWISE_DOCSTORE_ENDPOINTS = [
    "/api/v1/document-store/list",
    "/api/v1/document-store/store",
]
_FLOWISE_VECTOR_UPSERT = "/api/v1/vector/upsert/{flow_id}"

# Langflow session/conversation memory
_LANGFLOW_MEMORY_ENDPOINTS = [
    "/api/v1/monitor/messages",
    "/api/v1/monitor/transactions",
]

# Dify knowledge base (RAG) endpoints
_DIFY_DATASET_ENDPOINTS = [
    "/console/api/datasets",
    "/v1/datasets",
]

_PROBE_UPSERT_PAYLOAD = {
    "stopWords": [],
    "overrideConfig": {},
}


class MemoryPoisoningModule(BaseModule):
    name        = "memory-poisoning"
    owasp_id    = OWASPCategory.ASI06
    description = "Detects unauthenticated vectorstore access and document injection (ASI06)"

    async def run(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(await self._check_docstore(surface, platform))
        findings.extend(await self._check_memory(surface, platform))
        findings.extend(await self._check_vector_inject(surface, platform))
        findings.extend(await self._check_dify_datasets(surface, platform))
        return findings

    async def _check_docstore(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        findings = []
        for endpoint in _FLOWISE_DOCSTORE_ENDPOINTS:
            try:
                r = await platform.get(endpoint)
                if r.status_code == 200 and _is_api_response(r):
                    try:
                        data = r.json()
                        count = len(data) if isinstance(data, list) else 0
                    except Exception:
                        count = 0
                    findings.append(Finding(
                        title=f"Unauthenticated document store access: {endpoint}",
                        severity=Severity.HIGH,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The Flowise document store endpoint {endpoint} returns data without "
                            f"authentication. Exposed document stores leak RAG knowledge base "
                            f"content including proprietary documents and embeddings."
                        ),
                        evidence=(
                            f"GET {endpoint} → 200 OK"
                            + (f" ({count} document stores exposed)" if count else "")
                        ),
                        remediation=(
                            "Enable Flowise authentication (FLOWISE_USERNAME + FLOWISE_PASSWORD). "
                            "Restrict document store endpoints to authenticated users."
                        ),
                        confidence=90,
                        endpoint=endpoint,
                    ))
            except Exception:
                pass
        return findings

    async def _check_memory(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        findings = []
        for endpoint in _LANGFLOW_MEMORY_ENDPOINTS:
            try:
                r = await platform.get(endpoint)
                if r.status_code == 200 and _is_api_response(r):
                    try:
                        data = r.json()
                        count = len(data) if isinstance(data, list) else len(data.get("data", []))
                    except Exception:
                        count = 0
                    findings.append(Finding(
                        title=f"Unauthenticated conversation memory access: {endpoint}",
                        severity=Severity.HIGH,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The endpoint {endpoint} exposes conversation history and session "
                            f"memory without authentication. An attacker can read past user "
                            f"messages, injected prompts, and context from other sessions."
                        ),
                        evidence=(
                            f"GET {endpoint} → 200 OK"
                            + (f" ({count} records exposed)" if count else "")
                        ),
                        remediation=(
                            "Enable Langflow authentication and restrict monitor endpoints "
                            "to authenticated administrators."
                        ),
                        confidence=90,
                        endpoint=endpoint,
                    ))
            except Exception:
                pass
        return findings

    async def _check_vector_inject(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        """Flowise: probe unauthenticated vectorstore upsert (document injection)."""
        findings = []
        flow_ids = [f.get("id") for f in surface.flows if isinstance(f, dict) and f.get("id")]
        if not flow_ids:
            flow_ids = ["condor-probe"]
        for flow_id in flow_ids[:3]:
            endpoint = _FLOWISE_VECTOR_UPSERT.format(flow_id=flow_id)
            try:
                r = await platform.post(endpoint, json=_PROBE_UPSERT_PAYLOAD)
                if r.status_code in (200, 201, 202) and _is_api_response(r):
                    findings.append(Finding(
                        title=f"Unauthenticated vectorstore document injection: {endpoint}",
                        severity=Severity.CRITICAL,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The Flowise vectorstore upsert endpoint {endpoint} accepts document "
                            f"uploads without authentication. An attacker can poison the RAG "
                            f"knowledge base to manipulate agent responses, inject adversarial "
                            f"instructions, or exfiltrate data through retrieval."
                        ),
                        evidence=f"POST {endpoint} → {r.status_code} (document injection accepted)",
                        remediation=(
                            "Enable Flowise authentication. Restrict vector upsert endpoints "
                            "to authorized users only."
                        ),
                        confidence=90,
                        endpoint=endpoint,
                    ))
                    break
                elif r.status_code in (400, 422, 500) and _is_api_response(r):
                    # Endpoint exists and requires no auth — bad payload rejected, not unauthorized
                    findings.append(Finding(
                        title=f"Vectorstore upsert endpoint accessible without auth: {endpoint}",
                        severity=Severity.HIGH,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The Flowise vectorstore endpoint {endpoint} is reachable without "
                            f"authentication (returned {r.status_code} for probe payload). "
                            f"A correctly formatted request may inject documents into the RAG store."
                        ),
                        evidence=f"POST {endpoint} → {r.status_code} (auth not enforced)",
                        remediation=(
                            "Enable Flowise authentication. Restrict vector upsert endpoints "
                            "to authorized users only."
                        ),
                        confidence=70,
                        endpoint=endpoint,
                    ))
                    break
            except Exception:
                pass
        return findings

    async def _check_dify_datasets(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        findings = []
        for endpoint in _DIFY_DATASET_ENDPOINTS:
            try:
                r = await platform.get(endpoint)
                if r.status_code == 200 and _is_api_response(r):
                    try:
                        data = r.json()
                        count = len(data.get("data", [])) if isinstance(data, dict) else len(data)
                    except Exception:
                        count = 0
                    findings.append(Finding(
                        title=f"Unauthenticated knowledge base access: {endpoint}",
                        severity=Severity.HIGH,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The Dify endpoint {endpoint} exposes the knowledge base list without "
                            f"authentication. Exposed knowledge bases leak business documents and "
                            f"enable targeted RAG poisoning attacks."
                        ),
                        evidence=(
                            f"GET {endpoint} → 200 OK"
                            + (f" ({count} knowledge bases exposed)" if count else "")
                        ),
                        remediation=(
                            "Restrict Dify console API endpoints to authenticated users. "
                            "Use Dify's built-in access controls for knowledge bases."
                        ),
                        confidence=85,
                        endpoint=endpoint,
                    ))
            except Exception:
                pass
        return findings
