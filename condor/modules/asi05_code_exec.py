"""ASI05 — Unexpected Code Execution: eval/exec sinks in agentic platforms."""
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

# Flowise: node-load-method can execute arbitrary JS code
_FLOWISE_CODE_ENDPOINTS = [
    "/api/v1/node-load-method/jsFunctionNode",
    "/api/v1/node-load-method/ifElseFunction",
    "/api/v1/node-load-method/customFunction",
]

# Probe payload — benign side-channel: measure time difference
_JS_TIMING_PROBE = {"code": "return new Promise(r => setTimeout(() => r(42), 300))"}
_JS_EXEC_PROBE   = {"code": "return require('os').platform()"}

# AutoGen Studio — FunctionTool endpoint (found via Shrike: ASI05 RCE)
_AUTOGEN_EXEC_ENDPOINTS = [
    "/api/tools/execute",
    "/api/v1/tools/execute",
]
_AUTOGEN_EXEC_PAYLOAD = {"source_code": "import os; print(os.getcwd())", "name": "_probe_"}

# Langflow — custom component execution
_LANGFLOW_EXEC_ENDPOINTS = [
    "/api/v1/custom_component",
    "/api/v1/run/code",
]


class CodeExecutionModule(BaseModule):
    name        = "code-execution"
    owasp_id    = OWASPCategory.ASI05
    description = "Detects eval/exec sinks and unauthenticated code execution endpoints (ASI05)"

    async def run(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        findings: list[Finding] = []

        # Flowise: node-load-method JS execution
        for endpoint in _FLOWISE_CODE_ENDPOINTS:
            try:
                r = await platform.post(endpoint, json=_JS_EXEC_PROBE)
                if r.status_code == 200 and _is_api_response(r):
                    body = r.text
                    # If response contains OS info, it's confirmed RCE
                    os_indicators = ["linux", "darwin", "win32", "freebsd"]
                    confirmed = any(ind in body.lower() for ind in os_indicators)
                    findings.append(Finding(
                        title=f"Unauthenticated code execution via {endpoint}",
                        severity=Severity.CRITICAL,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The Flowise endpoint {endpoint} executes arbitrary JavaScript "
                            f"without authentication. An attacker can achieve full server-side "
                            f"code execution, read files, execute system commands, or pivot "
                            f"to internal services."
                        ),
                        evidence=(
                            f"POST {endpoint} with JS payload → 200 OK. "
                            + (f"OS info in response: {body[:200]}" if confirmed else "Endpoint accepted code payload.")
                        ),
                        remediation=(
                            "Enable Flowise authentication (FLOWISE_USERNAME + FLOWISE_PASSWORD). "
                            "Restrict the node-load-method endpoint to authenticated users only."
                        ),
                        confidence=95 if confirmed else 75,
                        endpoint=endpoint,
                    ))
            except Exception:
                pass

        # AutoGen Studio: tools/execute endpoint (Shrike-confirmed RCE pattern)
        for endpoint in _AUTOGEN_EXEC_ENDPOINTS:
            try:
                r = await platform.post(endpoint, json=_AUTOGEN_EXEC_PAYLOAD)
                if r.status_code in (200, 201) and _is_api_response(r):
                    findings.append(Finding(
                        title=f"Unauthenticated Python execution via {endpoint}",
                        severity=Severity.CRITICAL,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The AutoGen Studio endpoint {endpoint} accepts Python source code "
                            f"and executes it via exec() without authentication. "
                            f"This allows full server-side code execution."
                        ),
                        evidence=f"POST {endpoint} with Python payload → {r.status_code}",
                        remediation="Enable AutoGen Studio authentication and sandbox code execution.",
                        confidence=90,
                        endpoint=endpoint,
                    ))
            except Exception:
                pass

        # Langflow: custom component execution
        for endpoint in _LANGFLOW_EXEC_ENDPOINTS:
            try:
                r = await platform.post(endpoint, json={"code": "print('condor')", "frontend_node": {}})
                if r.status_code in (200, 201) and _is_api_response(r):
                    findings.append(Finding(
                        title=f"Code execution endpoint reachable: {endpoint}",
                        severity=Severity.HIGH,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The Langflow endpoint {endpoint} is accessible and may allow "
                            f"arbitrary Python execution. Requires further manual verification."
                        ),
                        evidence=f"POST {endpoint} → {r.status_code}",
                        remediation="Restrict custom component endpoints to authenticated users.",
                        confidence=65,
                        endpoint=endpoint,
                    ))
            except Exception:
                pass

        return findings
