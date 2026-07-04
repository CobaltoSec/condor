"""Flowise platform adapter — REST API v1."""
from __future__ import annotations

import base64

from .base import BasePlatform
from ..core.models import AgentSurface

# Flowise sensitive endpoints — checked during enumeration
_SENSITIVE_ENDPOINTS = [
    "/api/v1/chatflows",
    "/api/v1/credentials",
    "/api/v1/variables",
    "/api/v1/apikey",
    "/api/v1/tools",
    "/api/v1/nodes",
    "/api/v1/stats",
    "/api/v1/flow-config",
]


class FlowisePlatform(BasePlatform):
    name = "flowise"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self._api_key:
            self._headers["Authorization"] = f"Bearer {self._api_key}"
        elif self._username and self._password:
            creds = base64.b64encode(f"{self._username}:{self._password}".encode()).decode()
            self._headers["Authorization"] = f"Basic {creds}"

    async def health_check(self) -> bool:
        try:
            r = await self.get("/api/v1/chatflows")
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

        # Auth detection — Flowise returns 401/403 if auth is enabled
        try:
            r = await self.get("/api/v1/chatflows")
            surface.auth_required = r.status_code in (401, 403)
            if r.status_code == 200:
                flows = r.json()
                surface.flows = flows if isinstance(flows, list) else []
        except Exception:
            pass

        # Tools
        try:
            r = await self.get("/api/v1/tools")
            if r.status_code == 200:
                tools = r.json()
                surface.tools = tools if isinstance(tools, list) else []
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
