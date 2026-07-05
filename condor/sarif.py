"""SARIF 2.1.0 serialization for Condor scan results."""
from __future__ import annotations

from .core.models import ScanResult, Severity

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

_SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH:     "error",
    Severity.MEDIUM:   "warning",
    Severity.LOW:      "note",
    Severity.INFO:     "note",
}

_ASI_DESCRIPTIONS = {
    "ASI01": "Agent Goal Hijacking",
    "ASI02": "Tool Misuse & Exploitation",
    "ASI03": "Agent Identity & Privilege Abuse",
    "ASI04": "Agentic Supply Chain Compromise",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Agent Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}


def to_sarif(result: ScanResult, tool_version: str) -> dict:
    """Convert a ScanResult to a SARIF 2.1.0 document."""
    # Pre-pass: collect first remediation and CWE IDs per rule_id
    remediations: dict[str, str] = {}
    cwe_tags: dict[str, list[str]] = {}
    for f in result.findings:
        rule_id = f.owasp_id.value
        if f.remediation and rule_id not in remediations:
            remediations[rule_id] = f.remediation
        if f.cwe_id and f.cwe_id not in cwe_tags.get(rule_id, []):
            cwe_tags.setdefault(rule_id, []).append(f.cwe_id)

    seen_rules: dict[str, bool] = {}
    rules = []
    for f in result.findings:
        rule_id = f.owasp_id.value
        if rule_id not in seen_rules:
            seen_rules[rule_id] = True
            rule: dict = {
                "id": rule_id,
                "name": _ASI_DESCRIPTIONS.get(rule_id, rule_id),
                "shortDescription": {
                    "text": f"OWASP ASI {rule_id}: {_ASI_DESCRIPTIONS.get(rule_id, '')}",
                },
                "helpUri": "https://owasp.org/www-project-agentic-security-initiative/",
            }
            if rule_id in remediations:
                rule["help"] = {"text": remediations[rule_id]}
            tags = ["security"] + cwe_tags.get(rule_id, [])
            rule["properties"] = {"tags": tags}
            rules.append(rule)

    sarif_results = []
    for f in result.findings:
        uri = result.target.rstrip("/") + (f.endpoint or "")
        sarif_results.append({
            "ruleId": f.owasp_id.value,
            "level": _SEVERITY_TO_LEVEL.get(f.severity, "warning"),
            "message": {"text": f"[{f.title}] {f.description}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                    }
                }
            ],
            "partialFingerprints": {"condorConfidence": str(f.confidence)},
        })

    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "condor",
                        "version": tool_version,
                        "informationUri": "https://github.com/cobaltosec/condor",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }
