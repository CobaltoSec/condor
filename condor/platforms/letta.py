"""Letta (MemGPT) platform adapter — REST API v1."""
from __future__ import annotations

from .base import BasePlatform
from ..core.models import AgentSurface

_PROBE_ENDPOINTS = [
    "/v1/agents",
    "/v1/tools",
    "/v1/sources",
    "/v1/blocks",
    "/v1/health",
]


class LettaPlatform(BasePlatform):
    name = "letta"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self._api_key:
            self._headers["Authorization"] = f"Bearer {self._api_key}"

    async def health_check(self) -> bool:
        try:
            r = await self.get("/v1/health")
            if r.status_code < 500:
                return True
        except Exception:
            pass
        try:
            r = await self.get("/v1/agents")
            return r.status_code < 500
        except Exception:
            return False

    async def enumerate(self) -> AgentSurface:
        surface = AgentSurface(platform=self.name, base_url=self.base_url)

        # Version via health
        try:
            r = await self.get("/v1/health")
            if r.status_code == 200:
                data = r.json()
                surface.version = data.get("version")
        except Exception:
            pass

        # Agent enumeration
        try:
            r = await self.get("/v1/agents")
            surface.auth_required = r.status_code in (401, 403)
            if r.status_code == 200:
                data = r.json()
                agents = data if isinstance(data, list) else data.get("agents", [])
                surface.flows = agents
        except Exception:
            pass

        # Tools
        try:
            r = await self.get("/v1/tools")
            if r.status_code == 200:
                data = r.json()
                surface.tools = data if isinstance(data, list) else data.get("tools", [])
        except Exception:
            pass

        # Sources (RAG memory)
        try:
            r = await self.get("/v1/sources")
            if r.status_code == 200:
                data = r.json()
                surface.raw_info["sources"] = data if isinstance(data, list) else data.get("sources", [])
        except Exception:
            pass

        # Per-agent memory endpoints (IDOR surface for ASI06)
        accessible = list(_PROBE_ENDPOINTS)
        agent_ids = [a.get("id") for a in surface.flows[:3] if isinstance(a, dict) and a.get("id")]
        for aid in agent_ids:
            accessible.append(f"/v1/agents/{aid}/memory")
            accessible.append(f"/v1/agents/{aid}/messages")
        surface.endpoints = accessible

        return surface
