"""Tests for AutoGenPlatform adapter."""
import pytest
from unittest.mock import MagicMock, AsyncMock

from condor.platforms.autogen import AutoGenPlatform


def _json_resp(status: int, data) -> MagicMock:
    import json as _json
    r = MagicMock(status_code=status, text=_json.dumps(data), content=_json.dumps(data).encode())
    r.json.return_value = data
    return r


def test_platform_name():
    plat = AutoGenPlatform("http://localhost:8081")
    assert plat.name == "autogen"


@pytest.mark.asyncio
async def test_health_check_ok():
    plat = AutoGenPlatform("http://localhost:8081")
    plat.get = AsyncMock(return_value=MagicMock(status_code=200))
    result = await plat.health_check()
    assert result is True


@pytest.mark.asyncio
async def test_health_check_fail():
    plat = AutoGenPlatform("http://localhost:8081")
    plat.get = AsyncMock(return_value=MagicMock(status_code=500))
    result = await plat.health_check()
    assert result is False


@pytest.mark.asyncio
async def test_enumerate_version_and_teams():
    plat = AutoGenPlatform("http://localhost:8081")

    resp_version = _json_resp(200, {"version": "0.4.2"})
    resp_teams   = _json_resp(200, {"data": [{"id": "t1", "name": "research"}]})
    resp_tools   = _json_resp(200, {"data": [{"id": "tool1", "name": "web_search"}]})
    resp_404     = MagicMock(status_code=404)

    async def mock_get(path, **kw):
        return {
            "/api/version": resp_version,
            "/api/teams":   resp_teams,
            "/api/tools":   resp_tools,
        }.get(path, resp_404)

    plat.get = mock_get
    surface = await plat.enumerate()

    assert surface.version == "0.4.2"
    assert surface.auth_required is False
    assert len(surface.flows) == 1
    assert surface.flows[0]["name"] == "research"
    assert len(surface.tools) == 1
    assert surface.tools[0]["name"] == "web_search"


@pytest.mark.asyncio
async def test_enumerate_auth_required():
    plat = AutoGenPlatform("http://localhost:8081")

    resp_401 = MagicMock(status_code=401)
    resp_404 = MagicMock(status_code=404)

    async def mock_get(path, **kw):
        if path in ("/api/teams", "/api/v1/teams"):
            return resp_401
        return resp_404

    plat.get = mock_get
    surface = await plat.enumerate()

    assert surface.auth_required is True
    assert surface.flows == []
