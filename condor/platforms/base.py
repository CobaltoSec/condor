"""Base platform adapter — defines the interface all platform adapters implement."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

import httpx

from ..core.models import AgentSurface


class BasePlatform(ABC):
    """Abstract base for platform-specific API adapters."""

    name: str = "unknown"

    def __init__(self, base_url: str, timeout: int = 30, headers: dict | None = None):
        self.base_url = base_url.rstrip("/")
        self.timeout  = timeout
        self._headers = headers or {}
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "BasePlatform":
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout,
            headers=self._headers,
            follow_redirects=True,
        )
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._client:
            await self._client.aclose()

    async def get(self, path: str, **kwargs: Any) -> httpx.Response:
        assert self._client, "Use async context manager"
        return await self._client.get(path, **kwargs)

    async def post(self, path: str, **kwargs: Any) -> httpx.Response:
        assert self._client, "Use async context manager"
        return await self._client.post(path, **kwargs)

    async def delete(self, path: str, **kwargs: Any) -> httpx.Response:
        assert self._client, "Use async context manager"
        return await self._client.delete(path, **kwargs)

    @abstractmethod
    async def enumerate(self) -> AgentSurface:
        """Enumerate the platform's attack surface."""
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Return True if the platform is reachable."""
        ...
