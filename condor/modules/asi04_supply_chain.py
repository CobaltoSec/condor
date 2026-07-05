"""ASI04 — Agentic Supply Chain Compromise: CVE detection via OSV.dev + description injection."""
from __future__ import annotations

import re

import httpx

from .base import BaseModule
from ..core.models import AgentSurface, Finding, OWASPCategory, Severity
from ..platforms.base import BasePlatform

_OSV_API = "https://api.osv.dev/v1/query"

_INJECTION_PATTERNS = [
    re.compile(r'(ignore|disregard|forget)\s+.{0,30}(instruction|above|previous|system|prompt)', re.I),
    re.compile(r'(your\s+new\s+task|new\s+instruction|override\s+previous)', re.I),
    re.compile(r'(you\s+are\s+now|act\s+as|pretend\s+you\s+are).{0,30}(without\s+restriction|no\s+limit|unrestricted)', re.I),
    re.compile(r'(reveal|output|print|show|repeat).{0,20}(system\s+prompt|instruction|above|previous)', re.I),
    re.compile(r'(CONFIDENTIAL|SECRET|PRIVATE).{0,10}(do\s+not\s+share|never\s+reveal)', re.I),
]

_MAX_TOOLS_OSV = 10

_GENERIC_NAMES_SKIP_OSV = frozenset({
    "search", "file", "calculator", "json", "text", "web", "http", "api",
    "tool", "helper", "utils", "chat", "message", "data", "query", "fetch",
    "get", "post", "run", "execute", "retriever", "memory", "agent", "chain",
})


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


async def _query_osv_ecosystem(
    client: httpx.AsyncClient, tname: str, tver: str | None, ecosystem: str
) -> list[dict]:
    try:
        payload: dict = {"package": {"name": tname, "ecosystem": ecosystem}}
        if tver:
            payload["version"] = tver
        r = await client.post(_OSV_API, json=payload)
        if r.status_code != 200:
            return []
        return r.json().get("vulns", [])
    except Exception:
        return []


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

        # 3. CVE check via OSV.dev (npm + PyPI)
        checked: set[str] = set()
        async with httpx.AsyncClient(timeout=15) as client:
            for tool in surface.tools[:_MAX_TOOLS_OSV]:
                tname = _tool_name(tool)
                if not tname or tname in checked:
                    continue
                checked.add(tname)
                if tname.lower() in _GENERIC_NAMES_SKIP_OSV:
                    continue
                tver = _tool_version(tool)

                npm_vulns = await _query_osv_ecosystem(client, tname, tver, "npm")
                pypi_vulns = await _query_osv_ecosystem(client, tname, tver, "PyPI")

                # Track ecosystem per vuln ID, then deduplicate
                eco_map: dict[str, str] = {}
                for v in npm_vulns:
                    eco_map[v.get("id", "?")] = "npm"
                for v in pypi_vulns:
                    vid = v.get("id", "?")
                    eco_map[vid] = "npm+PyPI" if vid in eco_map else "PyPI"

                seen_ids: set[str] = set()
                all_vulns: list[dict] = []
                for v in npm_vulns + pypi_vulns:
                    vid = v.get("id", "")
                    if vid not in seen_ids:
                        seen_ids.add(vid)
                        all_vulns.append(v)

                if not all_vulns:
                    continue

                cve_ids: list[str] = []
                for v in all_vulns[:3]:
                    vid = v.get("id", "?")
                    eco = eco_map.get(vid, "?")
                    cve = next(
                        (a for a in v.get("aliases", []) if a.startswith("CVE-")),
                        vid,
                    )
                    cve_ids.append(f"{eco}: {cve}")

                sev = Severity.HIGH
                for v in all_vulns:
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
                        f"Tool '{tname}' has {len(all_vulns)} known vulnerability/vulnerabilities "
                        f"in the OSV.dev database. Compromised dependencies in agentic platforms "
                        f"can lead to data exfiltration, RCE, or supply chain attacks."
                    ),
                    evidence=(
                        f"OSV query for '{tname}'"
                        + (f" v{tver}" if tver else "")
                        + f" → {len(all_vulns)} vuln(s). CVEs: {', '.join(cve_ids)}"
                    ),
                    remediation=(
                        f"Update '{tname}' to a patched version. "
                        "Review OSV.dev for specific CVE details and upgrade paths. "
                        "Pin dependency versions and add supply chain monitoring."
                    ),
                    confidence=85,
                    endpoint="/api/v1/tools",
                ))

        return findings
