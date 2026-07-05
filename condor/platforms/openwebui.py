"""Open WebUI platform adapter — REST API v1."""
from __future__ import annotations

from .base import BasePlatform
from ..core.models import AgentSurface

_PROBE_ENDPOINTS = [
    "/api/v1/models",
    "/api/v1/tools",
    "/api/v1/functions",
    "/api/v1/users",
    "/api/v1/chats",
    "/api/v1/memories",
]


class OpenWebUIPlatform(BasePlatform):
    name = "openwebui"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self._api_key:
            self._headers["Authorization"] = f"Bearer {self._api_key}"

    async def health_check(self) -> bool:
        try:
            r = await self.get("/api/v1/models")
            return r.status_code < 500
        except Exception:
            return False

    async def enumerate(self) -> AgentSurface:
        surface = AgentSurface(platform=self.name, base_url=self.base_url)

        # Version
        try:
            r = await self.get("/api/v1/version")
            if r.status_code == 200:
                data = r.json()
                surface.version = data.get("version") if isinstance(data, dict) else str(data)
        except Exception:
            pass

        # Auth detection via models endpoint
        try:
            r = await self.get("/api/v1/models")
            surface.auth_required = r.status_code in (401, 403)
            if r.status_code == 200:
                data = r.json()
                items = data.get("data", data) if isinstance(data, dict) else data
                if isinstance(items, list):
                    surface.tools = items
        except Exception:
            pass

        # Tools endpoint (Python execution) — may override models list
        try:
            r = await self.get("/api/v1/tools")
            if r.status_code == 200:
                data = r.json()
                items = data if isinstance(data, list) else data.get("data", [])
                surface.tools = items
        except Exception:
            pass

        # Functions endpoint — Open WebUI unique Python execution surface
        try:
            r = await self.get("/api/v1/functions")
            if r.status_code == 200:
                data = r.json()
                items = data if isinstance(data, list) else data.get("data", [])
                surface.raw_info["functions"] = items
                if not surface.auth_required:
                    surface.raw_info["functions_unauth"] = True
        except Exception:
            pass

        # Users count — exposes admin surface
        try:
            r = await self.get("/api/v1/users")
            if r.status_code == 200:
                data = r.json()
                count = len(data) if isinstance(data, list) else len(data.get("data", []))
                surface.raw_info["users_count"] = count
        except Exception:
            pass

        # Probe endpoints
        accessible = []
        for ep in _PROBE_ENDPOINTS:
            try:
                r = await self.get(ep)
                if r.status_code != 404:
                    accessible.append(ep)
            except Exception:
                pass
        surface.endpoints = accessible

        return surface
