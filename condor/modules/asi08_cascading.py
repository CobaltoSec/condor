"""ASI08 — Cascading Agent Failures: missing rate limits, exposed task queues, unauthenticated job management."""
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


def _has_rate_limit_headers(r) -> bool:
    """Return True if response contains any standard rate-limiting headers."""
    _RL_HEADERS = frozenset([
        "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
        "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset",
        "retry-after",
    ])
    try:
        headers_lower = {k.lower(): v for k, v in r.headers.items()}
        return any(h in headers_lower for h in _RL_HEADERS)
    except Exception:
        return False


_INFERENCE_PROBE_ENDPOINTS = [
    "/api/v1/prediction/condor-probe",
    "/api/v1/predict",
    "/v1/chat-messages",
    "/api/runs",
]

_QUEUE_ENDPOINTS = [
    "/api/v1/queue",
    "/api/v1/tasks",
    "/api/v1/jobs",
]

_CANCEL_ENDPOINT = "/api/v1/queue/condor-probe"


class CascadingFailuresModule(BaseModule):
    name        = "cascading-failures"
    owasp_id    = OWASPCategory.ASI08
    description = "Detects missing rate limits, exposed task queues, and unauthenticated job management (ASI08)"

    async def run(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(await self._check_rate_limits(surface, platform))
        findings.extend(await self._check_task_queue(surface, platform))
        findings.extend(await self._check_job_cancellation(surface, platform))
        return findings

    async def _check_rate_limits(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        """Probe inference endpoints for absent rate-limiting headers."""
        findings = []
        endpoints = list(_INFERENCE_PROBE_ENDPOINTS)
        flow_ids = [f.get("id") for f in surface.flows if isinstance(f, dict) and f.get("id")]
        if flow_ids:
            endpoints.insert(0, f"/api/v1/prediction/{flow_ids[0]}")

        for endpoint in endpoints:
            try:
                r = await platform.get(endpoint)
                if r.status_code == 429:
                    findings.append(Finding(
                        title=f"Rate limiting active on inference endpoint: {endpoint}",
                        severity=Severity.INFO,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The endpoint {endpoint} returned 429 Too Many Requests, "
                            f"indicating rate limiting is enforced."
                        ),
                        evidence=f"GET {endpoint} → 429 (rate limiting active)",
                        remediation="No action needed — rate limiting is correctly configured.",
                        confidence=95,
                        endpoint=endpoint,
                    ))
                    break
                elif r.status_code in (200, 400, 405, 422) and _is_api_response(r) and not _has_rate_limit_headers(r):
                    findings.append(Finding(
                        title=f"No rate limiting on inference endpoint: {endpoint}",
                        severity=Severity.MEDIUM,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The endpoint {endpoint} does not return rate limiting headers "
                            f"(X-RateLimit-*, RateLimit-*, Retry-After). Without throttling, "
                            f"an attacker can flood inference requests to exhaust LLM API quotas, "
                            f"cause resource starvation, and trigger cascading failures across "
                            f"dependent agent pipelines."
                        ),
                        evidence=f"GET {endpoint} → {r.status_code} (no rate limit headers detected)",
                        remediation=(
                            "Implement rate limiting on all inference endpoints via a reverse proxy "
                            "(nginx, Caddy) or application-layer middleware. "
                            "Return standard RateLimit-* headers per RFC 6585."
                        ),
                        confidence=70,
                        endpoint=endpoint,
                    ))
                    break
            except Exception:
                pass
        return findings

    async def _check_task_queue(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        """Check for exposed task queue management endpoints without authentication."""
        findings = []
        for endpoint in _QUEUE_ENDPOINTS:
            try:
                r = await platform.get(endpoint)
                if r.status_code == 200 and _is_api_response(r):
                    try:
                        data = r.json()
                        count = len(data) if isinstance(data, list) else len(data.get("data", []))
                    except Exception:
                        count = 0
                    findings.append(Finding(
                        title=f"Unauthenticated task queue access: {endpoint}",
                        severity=Severity.HIGH,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The endpoint {endpoint} exposes the task queue without authentication. "
                            f"An attacker can enumerate pending agent jobs, infer workload patterns, "
                            f"and identify in-flight tasks for manipulation or cancellation, causing "
                            f"cascading failures across the agent pipeline."
                        ),
                        evidence=(
                            f"GET {endpoint} → 200 OK"
                            + (f" ({count} queued tasks exposed)" if count else "")
                        ),
                        remediation=(
                            "Restrict task queue endpoints to authenticated administrators. "
                            "Apply authentication middleware to all /queue, /tasks, and /jobs routes."
                        ),
                        confidence=85,
                        endpoint=endpoint,
                    ))
            except Exception:
                pass
        return findings

    async def _check_job_cancellation(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        """Check if job cancellation endpoint is accessible without authentication."""
        findings = []
        try:
            r = await platform.delete(_CANCEL_ENDPOINT)
            if r.status_code in (200, 204) and _is_api_response(r):
                findings.append(Finding(
                    title=f"Unauthenticated job cancellation accepted: {_CANCEL_ENDPOINT}",
                    severity=Severity.HIGH,
                    owasp_id=self.owasp_id,
                    description=(
                        f"The endpoint {_CANCEL_ENDPOINT} accepted a DELETE request without "
                        f"authentication. An attacker can cancel running agent tasks, causing "
                        f"incomplete executions and cascading failures in dependent pipelines."
                    ),
                    evidence=f"DELETE {_CANCEL_ENDPOINT} → {r.status_code} (task cancelled without auth)",
                    remediation=(
                        "Require authentication for all task management endpoints. "
                        "Validate that DELETE operations are restricted to the task owner or administrator."
                    ),
                    confidence=85,
                    endpoint=_CANCEL_ENDPOINT,
                ))
            elif r.status_code == 404 and _is_api_response(r):
                findings.append(Finding(
                    title=f"Job management endpoint accessible without auth: {_CANCEL_ENDPOINT}",
                    severity=Severity.MEDIUM,
                    owasp_id=self.owasp_id,
                    description=(
                        f"The endpoint {_CANCEL_ENDPOINT} returned 404 (task not found) for an "
                        f"unauthenticated DELETE request. The job management API is accessible without "
                        f"authentication — a valid job ID would allow task cancellation."
                    ),
                    evidence=f"DELETE {_CANCEL_ENDPOINT} → 404 (auth not enforced, task ID mismatch)",
                    remediation=(
                        "Return 401 Unauthorized for all unauthenticated requests to job management "
                        "endpoints, regardless of whether the resource exists."
                    ),
                    confidence=70,
                    endpoint=_CANCEL_ENDPOINT,
                ))
        except Exception:
            pass
        return findings
