"""Ollama platform adapter — local model server (unauthenticated by default)."""
from __future__ import annotations

from .base import BasePlatform
from ..core.models import AgentSurface

_WRITE_PROBE_ENDPOINTS = [
    "/api/pull",
    "/api/create",
    "/api/push",
]

_WRITE_PROBE_PAYLOAD = {"model": "condor-probe-nonexistent-xyz"}


class OllamaPlatform(BasePlatform):
    name = "ollama"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self._api_key:
            self._headers["Authorization"] = f"Bearer {self._api_key}"

    async def health_check(self) -> bool:
        try:
            r = await self.get("/api/tags")
            if r.status_code == 200:
                r.json()
                return True
        except Exception:
            pass
        return False

    async def enumerate(self) -> AgentSurface:
        surface = AgentSurface(
            platform=self.name,
            base_url=self.base_url,
            auth_required=bool(self._api_key),
        )

        # Model list + version
        try:
            r = await self.get("/api/tags")
            if r.status_code == 200:
                data = r.json()
                models = data.get("models", [])
                surface.flows = [
                    {"id": m.get("name", m.get("model", "")), "name": m.get("name", m.get("model", ""))}
                    for m in models
                    if m.get("name") or m.get("model")
                ]
                version = r.headers.get("X-Ollama-Version")
                if version:
                    surface.version = version
        except Exception:
            pass

        # Running models
        try:
            r = await self.get("/api/ps")
            if r.status_code == 200:
                data = r.json()
                surface.raw_info["running_models"] = data.get("models", [])
        except Exception:
            pass

        # Write endpoint probe (unauthenticated access check)
        open_write_endpoints: list[str] = []
        for ep in _WRITE_PROBE_ENDPOINTS:
            try:
                r = await self.post(ep, json=_WRITE_PROBE_PAYLOAD)
                if r.status_code not in (401, 403):
                    open_write_endpoints.append(ep)
            except Exception:
                pass
        surface.raw_info["write_endpoints_open"] = open_write_endpoints
        surface.endpoints = open_write_endpoints

        return surface
