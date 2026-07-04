"""Tests for LlamaIndexPlatform adapter."""
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from condor.platforms.llamaindex import LlamaIndexPlatform


def _json_resp(status: int, data) -> MagicMock:
    r = MagicMock(status_code=status, text=json.dumps(data), content=json.dumps(data).encode())
    r.json.return_value = data
    return r


def test_platform_name():
    assert LlamaIndexPlatform("http://localhost:8000").name == "llamaindex"


def test_api_key_sets_bearer_header():
    plat = LlamaIndexPlatform("http://localhost:8000", api_key="sk-test")
    assert plat._headers.get("Authorization") == "Bearer sk-test"


def test_no_auth_no_header():
    plat = LlamaIndexPlatform("http://localhost:8000")
    assert "Authorization" not in plat._headers


@pytest.mark.asyncio
async def test_health_check_ok():
    plat = LlamaIndexPlatform("http://localhost:8000")
    plat.get = AsyncMock(return_value=MagicMock(status_code=200))
    assert await plat.health_check() is True


@pytest.mark.asyncio
async def test_health_check_fail():
    plat = LlamaIndexPlatform("http://localhost:8000")
    plat.get = AsyncMock(return_value=MagicMock(status_code=500))
    assert await plat.health_check() is False


@pytest.mark.asyncio
async def test_enumerate_version_from_openapi():
    plat = LlamaIndexPlatform("http://localhost:8000")

    resp_404    = MagicMock(status_code=404)
    resp_openapi = _json_resp(200, {"openapi": "3.0.0", "info": {"title": "LlamaIndex", "version": "0.10.1"}})
    resp_agents  = _json_resp(200, [{"id": "a1", "name": "research_agent"}])
    resp_tools   = _json_resp(200, [{"id": "t1", "name": "web_search"}])

    async def mock_get(path, **kw):
        return {
            "/openapi.json":   resp_openapi,
            "/api/v1/agents":  resp_agents,
            "/api/v1/tools":   resp_tools,
        }.get(path, resp_404)

    plat.get = mock_get
    surface = await plat.enumerate()

    assert surface.version == "0.10.1"
    assert surface.auth_required is False
    assert len(surface.flows) == 1
    assert surface.flows[0]["name"] == "research_agent"
    assert len(surface.tools) == 1


@pytest.mark.asyncio
async def test_enumerate_auth_required():
    plat = LlamaIndexPlatform("http://localhost:8000")

    resp_403 = MagicMock(status_code=403)
    resp_404 = MagicMock(status_code=404)

    async def mock_get(path, **kw):
        if path in ("/api/v1/agents", "/api/agents", "/agents"):
            return resp_403
        return resp_404

    plat.get = mock_get
    surface = await plat.enumerate()

    assert surface.auth_required is True
    assert surface.flows == []
