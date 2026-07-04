"""Dify platform adapter — console API."""
from __future__ import annotations

from .base import BasePlatform
from ..core.models import AgentSurface

# Dify sensitive endpoints — checked during enumeration
_SENSITIVE_ENDPOINTS = [
    "/console/api/apps",
    "/console/api/datasets",
    "/console/api/workspaces/current/members",
    "/console/api/workspaces/current/tool-providers",
    "/console/api/workspaces/current/plugin/list",
    "/console/api/system-features",
    "/v1/info",
    "/v1/parameters",
]


class DifyPlatform(BasePlatform):
    name = "dify"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self._api_key:
            self._headers["Authorization"] = f"Bearer {self._api_key}"

    async def _authenticate(self) -> None:
        if not (self._username and self._password):
            return
        try:
            r = await self._client.post(
                "/console/api/login",
                json={"email": self._username, "password": self._password},
            )
            if r.status_code == 200:
                data = r.json()
                token = (
                    data.get("data", {}).get("access_token")
                    if isinstance(data.get("data"), dict)
                    else data.get("access_token") or data.get("token")
                )
                if token:
                    self._client.headers["Authorization"] = f"Bearer {token}"
        except Exception:
            pass

    async def health_check(self) -> bool:
        try:
            r = await self.get("/health")
            if r.status_code < 500:
                return True
        except Exception:
            pass
        try:
            r = await self.get("/console/api/ping")
            return r.status_code < 500
        except Exception:
            return False

    async def enumerate(self) -> AgentSurface:
        surface = AgentSurface(platform=self.name, base_url=self.base_url)

        # Version
        try:
            r = await self.get("/console/api/version")
            if r.status_code == 200:
                data = r.json()
                surface.version = data.get("version")
        except Exception:
            pass

        # Auth detection — Dify console returns 401/403 if not logged in
        try:
            r = await self.get("/console/api/apps")
            surface.auth_required = r.status_code in (401, 403)
            if r.status_code == 200:
                data = r.json()
                # Response may be {"data": [...]} or a list directly
                apps = data.get("data") if isinstance(data, dict) else data
                surface.flows = apps if isinstance(apps, list) else []
        except Exception:
            pass

        # Tools — tool providers installed in the workspace
        try:
            r = await self.get("/console/api/workspaces/current/tool-providers")
            if r.status_code == 200:
                data = r.json()
                tools = data.get("data") if isinstance(data, dict) else data
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
