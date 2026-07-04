"""CrewAI platform adapter — crewai serve (FastAPI local server)."""
from __future__ import annotations

from .base import BasePlatform
from ..core.models import AgentSurface

_SENSITIVE_ENDPOINTS = [
    "/docs",
    "/openapi.json",
    "/crews",
    "/agents",
    "/tasks",
    "/kickoff",
    "/status",
    "/api/crews",
    "/api/agents",
    "/inputs",
]

_HEALTH_ENDPOINTS  = ["/health", "/healthz", "/"]
_CREW_ENDPOINTS    = ["/crews", "/api/crews"]
_AGENT_ENDPOINTS   = ["/agents", "/api/agents"]


class CrewAIPlatform(BasePlatform):
    name = "crewai"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self._api_key:
            self._headers["Authorization"] = f"Bearer {self._api_key}"

    async def health_check(self) -> bool:
        for ep in _HEALTH_ENDPOINTS:
            try:
                r = await self.get(ep)
                if r.status_code < 500:
                    return True
            except Exception:
                pass
        return False

    async def enumerate(self) -> AgentSurface:
        surface = AgentSurface(platform=self.name, base_url=self.base_url)

        # Version — extract from OpenAPI spec (crewai serve has no dedicated version endpoint)
        try:
            r = await self.get("/openapi.json")
            if r.status_code == 200:
                surface.version = r.json().get("info", {}).get("version")
        except Exception:
            pass

        # Auth detection + crew enumeration (crews = "flows" in CrewAI)
        for ep in _CREW_ENDPOINTS:
            try:
                r = await self.get(ep)
                surface.auth_required = r.status_code in (401, 403)
                if r.status_code == 200:
                    data = r.json()
                    crews = data.get("crews") or data.get("data", data) if isinstance(data, dict) else data
                    surface.flows = crews if isinstance(crews, list) else []
                break
            except Exception:
                pass

        # Agent enumeration (agents carry tool definitions in CrewAI)
        for ep in _AGENT_ENDPOINTS:
            try:
                r = await self.get(ep)
                if r.status_code == 200:
                    data = r.json()
                    agents = data.get("agents") or data.get("data", data) if isinstance(data, dict) else data
                    surface.tools = agents if isinstance(agents, list) else []
                    if surface.tools:
                        break
            except Exception:
                pass

        # Discovered sensitive endpoints (non-404)
        accessible = []
        for ep in _SENSITIVE_ENDPOINTS:
            try:
                r = await self.get(ep)
                if r.status_code != 404:
                    accessible.append(ep)
            except Exception:
                pass
        surface.endpoints = accessible

        return surface
