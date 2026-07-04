"""Generic platform adapter — for unknown/custom deployments."""
from __future__ import annotations

import base64

from .base import BasePlatform
from ..core.models import AgentSurface

# Common endpoints across multiple agentic platforms
_COMMON_ENDPOINTS = [
    "/api/v1/chatflows", "/api/v1/flows", "/api/v1/agents",
    "/api/v1/credentials", "/api/v1/variables", "/api/v1/apikey",
    "/api/v1/tools", "/api/v1/nodes",
    "/v1/chat-messages",          # Dify
    "/api/v1/run",                # Langflow
    "/studio/api/teams",          # AutoGen Studio
    "/api/v1/prediction",
    "/health", "/healthz", "/_health",
    "/api/version", "/api/v1/version",
]


class GenericPlatform(BasePlatform):
    name = "generic"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self._api_key:
            self._headers["Authorization"] = f"Bearer {self._api_key}"
        elif self._username and self._password:
            creds = base64.b64encode(f"{self._username}:{self._password}".encode()).decode()
            self._headers["Authorization"] = f"Basic {creds}"

    async def health_check(self) -> bool:
        for path in ("/health", "/healthz", "/api/v1/chatflows", "/"):
            try:
                r = await self.get(path)
                if r.status_code < 500:
                    return True
            except Exception:
                continue
        return False

    async def enumerate(self) -> AgentSurface:
        surface = AgentSurface(platform=self.name, base_url=self.base_url)
        accessible = []
        for ep in _COMMON_ENDPOINTS:
            try:
                r = await self.get(ep)
                if r.status_code not in (404, 405):
                    accessible.append(ep)
                    if r.status_code in (401, 403):
                        surface.auth_required = True
            except Exception:
                pass
        surface.endpoints = accessible
        return surface
