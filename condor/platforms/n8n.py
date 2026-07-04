"""n8n platform adapter — workflow automation with AI nodes."""
from __future__ import annotations

from .base import BasePlatform
from ..core.models import AgentSurface

_SENSITIVE_ENDPOINTS = [
    "/api/v1/credentials",
    "/api/v1/executions",
    "/rest/settings",
    "/rest/activeWorkflows",
    "/api/v1/workflows",
    "/api/v1/users",
    "/rest/owner",
]

_HEALTH_ENDPOINTS   = ["/healthz", "/rest/settings", "/"]
_VERSION_ENDPOINTS  = ["/api/v1/version"]
_WORKFLOW_ENDPOINTS = ["/api/v1/workflows"]
_CRED_ENDPOINTS     = ["/api/v1/credentials"]


class N8nPlatform(BasePlatform):
    name = "n8n"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self._api_key:
            self._headers["X-N8N-API-KEY"] = self._api_key

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

        # Version
        for ep in _VERSION_ENDPOINTS:
            try:
                r = await self.get(ep)
                if r.status_code == 200:
                    data = r.json()
                    surface.version = data.get("version")
                    if surface.version:
                        break
            except Exception:
                pass

        # Auth detection + workflow enumeration
        for ep in _WORKFLOW_ENDPOINTS:
            try:
                r = await self.get(ep)
                surface.auth_required = r.status_code in (401, 403)
                if r.status_code == 200:
                    data = r.json()
                    # n8n returns {"data": [...], "nextCursor": null}
                    workflows = data.get("data", data) if isinstance(data, dict) else data
                    surface.flows = workflows if isinstance(workflows, list) else []
                break
            except Exception:
                pass

        # Credential types (not values — but listing them is still an info leak)
        for ep in _CRED_ENDPOINTS:
            try:
                r = await self.get(ep)
                if r.status_code == 200:
                    data = r.json()
                    creds = data.get("data", data) if isinstance(data, dict) else data
                    surface.tools = creds if isinstance(creds, list) else []
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
