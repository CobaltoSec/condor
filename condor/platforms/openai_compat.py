"""OpenAI-compatible platform adapter — covers vLLM, LocalAI, LM Studio, Jan, and similar."""
from __future__ import annotations

from .base import BasePlatform
from ..core.models import AgentSurface

_SENSITIVE_ENDPOINTS = [
    "/v1/assistants",
    "/v1/vector_stores",
    "/v1/files",
    "/v1/threads",
]


class OpenAICompatPlatform(BasePlatform):
    name = "openai-compat"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self._api_key:
            self._headers["Authorization"] = f"Bearer {self._api_key}"

    async def health_check(self) -> bool:
        try:
            r = await self.get("/v1/models")
            return r.status_code == 200
        except Exception:
            return False

    async def enumerate(self) -> AgentSurface:
        surface = AgentSurface(platform=self.name, base_url=self.base_url)

        # Models — primary surface + auth detection
        try:
            r = await self.get("/v1/models")
            if r.status_code in (401, 403):
                surface.auth_required = True
            elif r.status_code == 200:
                surface.auth_required = False
                data = r.json()
                models = data.get("data", []) if isinstance(data, dict) else []
                surface.flows = [
                    {"id": m.get("id", ""), "name": m.get("id", "")}
                    for m in models
                    if isinstance(m, dict) and m.get("id")
                ]
                version = r.headers.get("x-openai-version") or r.headers.get("openai-version")
                if version:
                    surface.version = version
        except Exception:
            pass

        # Sensitive endpoints
        accessible = []
        for ep in _SENSITIVE_ENDPOINTS:
            try:
                r = await self.get(ep)
                if r.status_code == 200:
                    key = ep.lstrip("/").replace("/", "_") + "_accessible"
                    surface.raw_info[key] = True
                    try:
                        data = r.json()
                        items = data.get("data", []) if isinstance(data, dict) else []
                        surface.raw_info[ep.lstrip("/").replace("/", "_") + "_count"] = len(items)
                    except Exception:
                        pass
                    accessible.append(ep)
            except Exception:
                pass

        surface.endpoints = accessible
        return surface
