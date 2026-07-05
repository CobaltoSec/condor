"""Hayhooks platform adapter — Haystack pipeline server."""
from __future__ import annotations

from .base import BasePlatform
from ..core.models import AgentSurface

_FALLBACK_ENDPOINTS = [
    "/status",
    "/pipelines",
    "/openapi.json",
    "/docs",
    "/redoc",
]


class HayhooksPlatform(BasePlatform):
    name = "hayhooks"

    async def health_check(self) -> bool:
        try:
            r = await self.get("/status")
            return r.status_code < 500
        except Exception:
            return False

    async def enumerate(self) -> AgentSurface:
        surface = AgentSurface(platform=self.name, base_url=self.base_url)

        # Version via status
        try:
            r = await self.get("/status")
            if r.status_code == 200:
                data = r.json()
                surface.version = data.get("version") or data.get("hayhooks_version")
        except Exception:
            pass

        # Pipeline enumeration
        try:
            r = await self.get("/pipelines")
            surface.auth_required = r.status_code in (401, 403)
            if r.status_code == 200:
                data = r.json()
                items = data if isinstance(data, list) else data.get("pipelines", [])
                flows = []
                for item in items:
                    if isinstance(item, str):
                        flows.append({"id": item, "name": item})
                    elif isinstance(item, dict):
                        flows.append(item)
                surface.flows = flows
        except Exception:
            pass

        # OpenAPI spec — extract all paths
        try:
            r = await self.get("/openapi.json")
            if r.status_code == 200:
                data = r.json()
                paths = list(data.get("paths", {}).keys())
                surface.endpoints = paths if paths else _FALLBACK_ENDPOINTS
                return surface
        except Exception:
            pass

        # Fallback endpoint list
        accessible = []
        for ep in _FALLBACK_ENDPOINTS:
            try:
                r = await self.get(ep)
                if r.status_code != 404:
                    accessible.append(ep)
            except Exception:
                pass
        surface.endpoints = accessible

        return surface
