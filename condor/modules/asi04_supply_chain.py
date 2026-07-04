"""ASI04 — Agentic Supply Chain Compromise: CVE detection via OSV.dev + description injection."""
from __future__ import annotations

import re

import httpx

from .base import BaseModule
from ..core.models import AgentSurface, Finding, OWASPCategory, Severity
from ..platforms.base import BasePlatform

_OSV_API = "https://api.osv.dev/v1/query"

# Patterns that indicate a poisoned tool description
_INJECTION_PATTERNS = [
    re.compile(r"\b(ignore|forget|disregard|override)\b", re.IGNORECASE),
    re.compile(r"new instruction", re.IGNORECASE),
    re.compile(r"\b(send to|exfiltrate|webhook)\b", re.IGNORECASE),
    re.compile(r"https?://", re.IGNORECASE),
    re.compile(r"\b(admin|sudo|root|elevated)\b", re.IGNORECASE),
]

_MAX_TOOLS_OSV = 10


def _tool_name(tool: dict) -> str | None:
    return tool.get("name") or tool.get("packageName") or tool.get("package")


def _tool_version(tool: dict) -> str | None:
    return tool.get("version")


def _first_suspicious_match(text: str) -> str | None:
    for pat in _INJECTION_PATTERNS:
        m = pat.search(text)
        if m:
            start = max(0, m.start() - 30)
            end   = min(len(text), m.end() + 60)
            return f"...{text[start:end]}..."
    return None


class SupplyChainModule(BaseModule):
    name        = "supply-chain"
    owasp_id    = OWASPCategory.ASI04
    description = "Detects tools with CVEs (OSV.dev) and poisoned tool descriptions (ASI04)"

    async def run(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        findings: list[Finding] = []

        if not surface.tools:
            return findings

        # 1. Tool registry exposed without auth
        if not surface.auth_required:
            findings.append(Finding(
                title="Tool registry exposed without authentication",
                severity=Severity.HIGH,
                owasp_id=self.owasp_id,
                description=(
                    "The platform exposes its full tool registry to unauthenticated requests. "
                    "An attacker can enumerate all registered tools, their descriptions, and "
                    "schemas to plan further attacks or identify injection targets."
                ),
                evidence=f"/api/v1/tools → {len(surface.tools)} tool(s) returned without auth",
                remediation=(
                    "Enable platform authentication. For Flowise: set FLOWISE_USERNAME and "
                    "FLOWISE_PASSWORD. Restrict the /api/v1/tools endpoint to authenticated sessions."
                ),
                confidence=90,
                endpoint="/api/v1/tools",
            ))

        # 2. Description injection check
        for tool in surface.tools:
            desc = tool.get("description") or tool.get("desc") or ""
            if not desc:
                continue
            snippet = _first_suspicious_match(desc)
            if snippet:
                tname = _tool_name(tool) or "<unnamed>"
                findings.append(Finding(
                    title=f"Suspicious tool description — potential supply chain injection: {tname}",
                    severity=Severity.MEDIUM,
                    owasp_id=self.owasp_id,
                    description=(
                        f"Tool '{tname}' contains patterns in its description that may indicate "
                        f"a prompt injection payload embedded at install time. A compromised tool "
                        f"description can redirect the agent's behavior when the tool is invoked."
                    ),
                    evidence=f"Tool: {tname!r}\nSuspicious fragment: {snippet}",
                    remediation=(
                        "Audit tool descriptions for injected instructions. "
                        "Pin tool versions and verify descriptions against a trusted source. "
                        "Consider an LLM-based guard that scans tool metadata before registration."
                    ),
                    confidence=70,
                    endpoint="/api/v1/tools",
                ))

        # 3. CVE check via OSV.dev
        checked: set[str] = set()
        async with httpx.AsyncClient(timeout=15) as client:
            for tool in surface.tools[:_MAX_TOOLS_OSV]:
                tname = _tool_name(tool)
                if not tname or tname in checked:
                    continue
                checked.add(tname)
                try:
                    payload: dict = {"package": {"name": tname, "ecosystem": "npm"}}
                    tver = _tool_version(tool)
                    if tver:
                        payload["version"] = tver
                    r = await client.post(_OSV_API, json=payload)
                    if r.status_code != 200:
                        continue
                    data = r.json()
                    vulns = data.get("vulns", [])
                    if not vulns:
                        continue

                    cve_ids = [
                        alias
                        for v in vulns[:3]
                        for alias in v.get("aliases", [v.get("id", "")])
                        if alias.startswith("CVE-")
                    ][:3]
                    if not cve_ids:
                        cve_ids = [v.get("id", "?") for v in vulns[:3]]

                    # Determine severity from CVSS if present
                    sev = Severity.HIGH
                    for v in vulns:
                        for sev_info in v.get("severity", []):
                            score_str = sev_info.get("score", "")
                            try:
                                score = float(score_str)
                                if score >= 9.0:
                                    sev = Severity.CRITICAL
                                    break
                            except (ValueError, TypeError):
                                pass

                    findings.append(Finding(
                        title=f"Tool with known CVEs: {tname}",
                        severity=sev,
                        owasp_id=self.owasp_id,
                        description=(
                            f"Tool '{tname}' has {len(vulns)} known vulnerability/vulnerabilities "
                            f"in the OSV.dev database. Compromised dependencies in agentic platforms "
                            f"can lead to data exfiltration, RCE, or supply chain attacks."
                        ),
                        evidence=(
                            f"OSV query for '{tname}'"
                            + (f" v{tver}" if tver else "")
                            + f" → {len(vulns)} vuln(s). CVEs: {', '.join(cve_ids)}"
                        ),
                        remediation=(
                            f"Update '{tname}' to a patched version. "
                            "Review OSV.dev for specific CVE details and upgrade paths. "
                            "Pin dependency versions and add supply chain monitoring."
                        ),
                        confidence=85,
                        endpoint="/api/v1/tools",
                    ))
                except Exception:
                    pass

        return findings
