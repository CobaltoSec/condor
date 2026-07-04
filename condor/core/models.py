"""Core data models for Condor."""
from __future__ import annotations

import datetime
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class OWASPCategory(str, Enum):
    ASI01 = "ASI01"  # Agent Goal Hijack
    ASI02 = "ASI02"  # Tool Misuse & Exploitation
    ASI03 = "ASI03"  # Agent Identity & Privilege Abuse
    ASI04 = "ASI04"  # Agentic Supply Chain Compromise
    ASI05 = "ASI05"  # Unexpected Code Execution
    ASI06 = "ASI06"  # Memory & Context Poisoning
    ASI07 = "ASI07"  # Insecure Inter-Agent Communication
    ASI08 = "ASI08"  # Cascading Agent Failures
    ASI09 = "ASI09"  # Human-Agent Trust Exploitation
    ASI10 = "ASI10"  # Rogue Agents


class Finding(BaseModel):
    title:       str
    severity:    Severity
    owasp_id:    OWASPCategory
    description: str
    evidence:    str = ""
    remediation: str = ""
    confidence:  int = Field(default=80)
    endpoint:    str = ""

    def model_post_init(self, __context: Any) -> None:
        self.confidence = max(0, min(100, self.confidence))


class AgentSurface(BaseModel):
    """Enumerated attack surface of an agentic platform."""
    platform:    str
    base_url:    str
    version:     str | None = None
    auth_required: bool = False
    flows:       list[dict] = Field(default_factory=list)   # chatflows / workflows
    tools:       list[dict] = Field(default_factory=list)   # tools / nodes
    endpoints:   list[str]  = Field(default_factory=list)   # discovered HTTP endpoints
    raw_info:    dict       = Field(default_factory=dict)


class ScanResult(BaseModel):
    target:           str
    platform:         str
    findings:         list[Finding]    = Field(default_factory=list)
    modules_run:      list[str]        = Field(default_factory=list)
    surface:          AgentSurface | None = None
    started_at:       datetime.datetime | None = None
    finished_at:      datetime.datetime | None = None
    duration_seconds: float | None = None

    @property
    def finding_count(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts
