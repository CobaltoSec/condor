"""Tests for CrewAIPlatform adapter."""
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from condor.platforms.crewai import CrewAIPlatform


def _json_resp(status: int, data) -> MagicMock:
    r = MagicMock(status_code=status, text=json.dumps(data), content=json.dumps(data).encode())
    r.json.return_value = data
    return r


def test_platform_name():
    assert CrewAIPlatform("http://localhost:8080").name == "crewai"


def test_api_key_sets_bearer_header():
    plat = CrewAIPlatform("http://localhost:8080", api_key="tok123")
    assert plat._headers.get("Authorization") == "Bearer tok123"


def test_no_auth_no_header():
    plat = CrewAIPlatform("http://localhost:8080")
    assert "Authorization" not in plat._headers


@pytest.mark.asyncio
async def test_health_check_ok():
    plat = CrewAIPlatform("http://localhost:8080")
    plat.get = AsyncMock(return_value=MagicMock(status_code=200))
    assert await plat.health_check() is True


@pytest.mark.asyncio
async def test_health_check_fail():
    plat = CrewAIPlatform("http://localhost:8080")
    plat.get = AsyncMock(return_value=MagicMock(status_code=500))
    assert await plat.health_check() is False


@pytest.mark.asyncio
async def test_enumerate_version_and_crews():
    plat = CrewAIPlatform("http://localhost:8080")

    resp_openapi = _json_resp(200, {"info": {"title": "CrewAI API", "version": "0.80.0"}})
    resp_crews   = _json_resp(200, [{"id": "c1", "name": "research_crew"}])
    resp_agents  = _json_resp(200, [{"id": "ag1", "name": "researcher", "tools": ["web_search"]}])
    resp_404     = MagicMock(status_code=404)

    async def mock_get(path, **kw):
        return {
            "/openapi.json": resp_openapi,
            "/crews":        resp_crews,
            "/agents":       resp_agents,
        }.get(path, resp_404)

    plat.get = mock_get
    surface = await plat.enumerate()

    assert surface.version == "0.80.0"
    assert surface.auth_required is False
    assert len(surface.flows) == 1
    assert surface.flows[0]["name"] == "research_crew"
    assert len(surface.tools) == 1
    assert surface.tools[0]["name"] == "researcher"


@pytest.mark.asyncio
async def test_enumerate_auth_required():
    plat = CrewAIPlatform("http://localhost:8080")

    resp_401 = MagicMock(status_code=401)
    resp_404 = MagicMock(status_code=404)

    async def mock_get(path, **kw):
        if path in ("/crews", "/api/crews"):
            return resp_401
        return resp_404

    plat.get = mock_get
    surface = await plat.enumerate()

    assert surface.auth_required is True
    assert surface.flows == []


@pytest.mark.asyncio
async def test_enumerate_sensitive_endpoints_discovered():
    plat = CrewAIPlatform("http://localhost:8080")

    resp_200 = MagicMock(status_code=200)
    resp_404 = MagicMock(status_code=404)

    async def mock_get(path, **kw):
        if path in ("/docs", "/openapi.json", "/kickoff"):
            resp_200.json = MagicMock(return_value={"info": {}})
            return resp_200
        return resp_404

    plat.get = mock_get
    surface = await plat.enumerate()

    assert "/docs" in surface.endpoints
    assert "/kickoff" in surface.endpoints
