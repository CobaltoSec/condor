"""AutoGen Studio platform adapter."""
from __future__ import annotations

from .base import BasePlatform
from ..core.models import AgentSurface

_SENSITIVE_ENDPOINTS = [
    "/api/agents",
    "/api/teams",
    "/api/sessions",
    "/api/runs",
    "/api/models",
    "/api/tools",
    "/api/skills",
    "/api/v1/agents",
    "/api/v1/teams",
    "/api/v1/sessions",
    "/api/v1/runs",
    "/api/v1/models",
    "/api/v1/tools",
]

_HEALTH_ENDPOINTS = ["/healthz", "/api/version", "/api/v1/version", "/"]
_VERSION_ENDPOINTS = ["/api/version", "/api/v1/version"]
_TEAMS_ENDPOINTS   = ["/api/teams", "/api/v1/teams"]
_TOOLS_ENDPOINTS   = ["/api/tools", "/api/v1/tools", "/api/skills"]


class AutoGenPlatform(BasePlatform):
    name = "autogen"

    async def health_check(self) -> bool:
        for endpoint in _HEALTH_ENDPOINTS:
            try:
                r = await self.get(endpoint)
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
                    surface.version = data.get("version") or data.get("app_version")
                    if surface.version:
                        break
            except Exception:
                pass

        # Auth detection + team enumeration (teams = "flows" in AutoGen)
        for ep in _TEAMS_ENDPOINTS:
            try:
                r = await self.get(ep)
                surface.auth_required = r.status_code in (401, 403)
                if r.status_code == 200:
                    data = r.json()
                    teams = data.get("data", data) if isinstance(data, dict) else data
                    surface.flows = teams if isinstance(teams, list) else []
                break
            except Exception:
                pass

        # Tools/skills
        for ep in _TOOLS_ENDPOINTS:
            try:
                r = await self.get(ep)
                if r.status_code == 200:
                    data = r.json()
                    tools = data.get("data", data) if isinstance(data, dict) else data
                    surface.tools = tools if isinstance(tools, list) else []
                    if surface.tools:
                        break
            except Exception:
                pass

        # Discovered endpoints (non-404 responses)
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
