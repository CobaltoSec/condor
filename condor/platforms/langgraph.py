"""LangGraph Platform adapter — LangGraph Server (self-hosted)."""
from __future__ import annotations

from .base import BasePlatform
from ..core.models import AgentSurface


class LangGraphPlatform(BasePlatform):
    name = "langgraph"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self._api_key:
            self._headers["x-api-key"] = self._api_key

    async def health_check(self) -> bool:
        try:
            r = await self.get("/ok")
            return r.status_code == 200
        except Exception:
            return False

    async def enumerate(self) -> AgentSurface:
        surface = AgentSurface(platform=self.name, base_url=self.base_url)
        auth_signals: list[bool] = []
        reachable: list[str] = []

        # Assistants (agents)
        try:
            r = await self.get("/assistants")
            if r.status_code in (401, 403):
                auth_signals.append(True)
                reachable.append("/assistants")
            elif r.status_code == 200:
                auth_signals.append(False)
                reachable.append("/assistants")
                data = r.json()
                surface.flows = data if isinstance(data, list) else []
        except Exception:
            pass

        # Threads (conversation memory)
        try:
            r = await self.get("/threads")
            if r.status_code in (401, 403):
                auth_signals.append(True)
                reachable.append("/threads")
            elif r.status_code == 200:
                auth_signals.append(False)
                reachable.append("/threads")
                data = r.json()
                threads = data if isinstance(data, list) else []
                surface.raw_info["threads"] = len(threads)
        except Exception:
            pass

        # Persistent key-value store
        try:
            r = await self.get("/store/items")
            if r.status_code in (401, 403):
                auth_signals.append(True)
                reachable.append("/store/items")
            elif r.status_code == 200:
                auth_signals.append(False)
                reachable.append("/store/items")
                surface.raw_info["store_accessible"] = True
        except Exception:
            pass

        # Runs (execution history)
        try:
            r = await self.get("/runs")
            if r.status_code in (401, 403):
                auth_signals.append(True)
                reachable.append("/runs")
            elif r.status_code == 200:
                auth_signals.append(False)
                reachable.append("/runs")
                surface.raw_info["runs_accessible"] = True
        except Exception:
            pass

        if auth_signals:
            surface.auth_required = any(auth_signals)

        surface.endpoints = reachable

        return surface
