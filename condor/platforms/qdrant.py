"""Qdrant vector database platform adapter."""
from __future__ import annotations

from .base import BasePlatform
from ..core.models import AgentSurface

_PROBE_ENDPOINTS = [
    "/collections",
    "/cluster",
    "/telemetry",
    "/metrics",
    "/healthz",
    "/readyz",
]


class QdrantPlatform(BasePlatform):
    name = "qdrant"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self._api_key:
            self._headers["api-key"] = self._api_key

    async def health_check(self) -> bool:
        try:
            r = await self.get("/healthz")
            if r.status_code < 500:
                return True
        except Exception:
            pass
        try:
            r = await self.get("/collections")
            return r.status_code < 500
        except Exception:
            return False

    async def enumerate(self) -> AgentSurface:
        surface = AgentSurface(platform=self.name, base_url=self.base_url)

        # Version via telemetry
        try:
            r = await self.get("/telemetry")
            if r.status_code == 200:
                data = r.json()
                result = data.get("result", data)
                version = (result.get("version") if isinstance(result, dict) else None)
                surface.version = version
        except Exception:
            pass

        # Collection enumeration
        try:
            r = await self.get("/collections")
            surface.auth_required = r.status_code in (401, 403)
            if r.status_code == 200:
                data = r.json()
                result = data.get("result", {})
                collections = result.get("collections", []) if isinstance(result, dict) else []
                surface.raw_info["collections"] = collections
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
