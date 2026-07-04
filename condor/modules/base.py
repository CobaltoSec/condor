"""Base module — all attack modules inherit from this."""
from __future__ import annotations

from abc import ABC, abstractmethod

from ..core.models import AgentSurface, Finding, OWASPCategory
from ..platforms.base import BasePlatform


class BaseModule(ABC):
    name:        str          = "unnamed"
    owasp_id:    OWASPCategory = OWASPCategory.ASI01
    description: str          = ""

    @abstractmethod
    async def run(self, surface: AgentSurface, platform: BasePlatform) -> list[Finding]:
        """Execute the module and return findings."""
        ...
