"""Chroma vector database platform adapter."""
from __future__ import annotations

from .base import BasePlatform
from ..core.models import AgentSurface

_BASE_ENDPOINTS = [
    "/api/v1/heartbeat",
    "/api/v1/version",
    "/api/v1/collections",
]


class ChromaPlatform(BasePlatform):
    name = "chroma"

    async def health_check(self) -> bool:
        try:
            r = await self.get("/api/v1/heartbeat")
            return r.status_code < 500
        except Exception:
            return False

    async def enumerate(self) -> AgentSurface:
        surface = AgentSurface(platform=self.name, base_url=self.base_url)

        # Version — Chroma returns bare quoted string e.g. "0.5.11"
        try:
            r = await self.get("/api/v1/version")
            if r.status_code == 200:
                surface.version = r.text.strip().strip('"')
        except Exception:
            pass

        # Collection enumeration
        collections: list = []
        try:
            r = await self.get("/api/v1/collections")
            surface.auth_required = r.status_code in (401, 403)
            if r.status_code == 200:
                data = r.json()
                items = data if isinstance(data, list) else []
                names = [c.get("name") for c in items if isinstance(c, dict) and c.get("name")]
                surface.raw_info["collections"] = names
                collections = names
        except Exception:
            pass

        # Endpoints: base + per-collection
        endpoints = list(_BASE_ENDPOINTS)
        for name in collections[:5]:
            endpoints.append(f"/api/v1/collections/{name}")
        surface.endpoints = endpoints

        return surface
