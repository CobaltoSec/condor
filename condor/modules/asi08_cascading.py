"""ASI08 — Cascading Agent Failures: missing rate limits, exposed task queues, unauthenticated job management."""
from __future__ import annotations

import asyncio

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

_BURST_SIZE = 30
_BURST_PROBE_PAYLOAD = {"question": "condor-probe", "stream": False}


class CascadingFailuresModule(BaseModule):
    name        = "cascading-failures"
    owasp_id    = OWASPCategory.ASI08
    description = "Detects missing rate limits, exposed task queues, and unauthenticated job management (ASI08)"

    async def run(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(await self._check_rate_limits(surface, platform))
        findings.extend(await self._check_rate_limit_burst(surface, platform))
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
                        cwe_id="CWE-770",
                        endpoint=endpoint,
                    ))
                    break
            except Exception:
                pass
        return findings

    async def _check_rate_limit_burst(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        """Send a burst of concurrent requests and confirm whether rate limiting is enforced."""
        findings = []
        endpoints: list[str] = []
        flow_ids = [f.get("id") for f in surface.flows if isinstance(f, dict) and f.get("id")]
        if flow_ids:
            endpoints.append(f"/api/v1/prediction/{flow_ids[0]}")
        endpoints.extend(_INFERENCE_PROBE_ENDPOINTS)

        for endpoint in endpoints:
            try:
                responses = await asyncio.gather(
                    *[platform.post(endpoint, json=_BURST_PROBE_PAYLOAD) for _ in range(_BURST_SIZE)],
                    return_exceptions=True,
                )
                valid = [r for r in responses if not isinstance(r, Exception) and _is_api_response(r)]
                if not valid:
                    continue
                status_codes = [r.status_code for r in valid]
                if any(sc == 429 for sc in status_codes):
                    break  # rate limiting confirmed active
                if _has_rate_limit_headers(valid[0]):
                    break  # rate limit headers present — consider it configured
                if any(sc in (200, 201, 400, 405, 422) for sc in status_codes):
                    findings.append(Finding(
                        title=f"No Rate Limiting Detected Under Burst Load: {endpoint}",
                        severity=Severity.MEDIUM,
                        owasp_id=self.owasp_id,
                        description=(
                            f"Sending {_BURST_SIZE} concurrent requests to {endpoint} produced no 429 "
                            f"responses and no rate-limiting headers, indicating the endpoint has no "
                            f"effective throttling. An attacker can flood inference requests to exhaust "
                            f"LLM API quotas, cause resource starvation, and trigger cascading failures."
                        ),
                        evidence=(
                            f"POST {endpoint} × {_BURST_SIZE} concurrent → "
                            f"status codes: {status_codes} (no 429 returned)"
                        ),
                        remediation=(
                            "Implement rate limiting on all inference endpoints via a reverse proxy "
                            "(nginx, Caddy) or application-layer middleware. "
                            "Return 429 with Retry-After header when limits are exceeded."
                        ),
                        confidence=75,
                        cwe_id="CWE-770",
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
                        cwe_id="CWE-284",
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
                    cwe_id="CWE-284",
                    endpoint=_CANCEL_ENDPOINT,
                ))
            # 404 alone is ambiguous (endpoint may not exist at all) — not reported
        except Exception:
            pass
        return findings
