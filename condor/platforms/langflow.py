"""Langflow platform adapter — REST API v1."""
from __future__ import annotations

from .base import BasePlatform
from ..core.models import AgentSurface

# Langflow sensitive endpoints — checked during enumeration
_SENSITIVE_ENDPOINTS = [
    "/api/v1/flows",
    "/api/v1/variables",
    "/api/v1/files/list",
    "/api/v1/api_key",
    "/api/v1/config",
    "/api/v1/store/components",
    "/api/v1/monitor/messages",
    "/api/v1/monitor/transactions",
]


class LangflowPlatform(BasePlatform):
    name = "langflow"

    async def health_check(self) -> bool:
        try:
            r = await self.get("/health")
            if r.status_code < 500:
                return True
        except Exception:
            pass
        try:
            r = await self.get("/api/v1/flows")
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
                surface.version = data.get("version")
        except Exception:
            pass

        # Auth detection — Langflow returns 401/403 if auth is enabled
        try:
            r = await self.get("/api/v1/flows")
            surface.auth_required = r.status_code in (401, 403)
            if r.status_code == 200:
                flows = r.json()
                surface.flows = flows if isinstance(flows, list) else []
        except Exception:
            pass

        # Components (tools equivalent)
        for ep in ("/api/v1/components", "/api/v1/store/components"):
            try:
                r = await self.get(ep)
                if r.status_code == 200:
                    data = r.json()
                    surface.tools = data if isinstance(data, list) else []
                    break
            except Exception:
                pass

        # Discovered endpoints (which responded without 404)
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
