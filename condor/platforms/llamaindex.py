"""LlamaIndex platform adapter — llama-agents / llama-index-server (FastAPI)."""
from __future__ import annotations

from .base import BasePlatform
from ..core.models import AgentSurface

_SENSITIVE_ENDPOINTS = [
    "/docs",
    "/openapi.json",
    "/api/v1/agents",
    "/api/v1/tools",
    "/api/agents",
    "/api/tools",
    "/queue/tasks",
    "/queue/services",
    "/api/v1/chat",
    "/api/chat",
]

_HEALTH_ENDPOINTS   = ["/health", "/healthz", "/"]
_VERSION_ENDPOINTS  = ["/api/v1/version", "/openapi.json"]
_AGENT_ENDPOINTS    = ["/api/v1/agents", "/api/agents", "/agents"]
_TOOL_ENDPOINTS     = ["/api/v1/tools", "/api/tools", "/tools"]


class LlamaIndexPlatform(BasePlatform):
    name = "llamaindex"

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

        # Version — try dedicated endpoint, then extract from OpenAPI spec
        try:
            r = await self.get("/api/v1/version")
            if r.status_code == 200:
                surface.version = r.json().get("version")
        except Exception:
            pass
        if not surface.version:
            try:
                r = await self.get("/openapi.json")
                if r.status_code == 200:
                    surface.version = r.json().get("info", {}).get("version")
            except Exception:
                pass

        # Auth detection + agent enumeration
        for ep in _AGENT_ENDPOINTS:
            try:
                r = await self.get(ep)
                surface.auth_required = r.status_code in (401, 403)
                if r.status_code == 200:
                    data = r.json()
                    agents = data.get("agents") or data.get("data", data) if isinstance(data, dict) else data
                    surface.flows = agents if isinstance(agents, list) else []
                break
            except Exception:
                pass

        # Tool enumeration
        for ep in _TOOL_ENDPOINTS:
            try:
                r = await self.get(ep)
                if r.status_code == 200:
                    data = r.json()
                    tools = data.get("tools") or data.get("data", data) if isinstance(data, dict) else data
                    surface.tools = tools if isinstance(tools, list) else []
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
