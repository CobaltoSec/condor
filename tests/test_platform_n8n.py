"""Tests for N8nPlatform adapter."""
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from condor.platforms.n8n import N8nPlatform


def _json_resp(status: int, data) -> MagicMock:
    r = MagicMock(status_code=status, text=json.dumps(data), content=json.dumps(data).encode())
    r.json.return_value = data
    return r


def test_platform_name():
    assert N8nPlatform("http://localhost:5678").name == "n8n"


def test_api_key_sets_header():
    plat = N8nPlatform("http://localhost:5678", api_key="mykey")
    assert plat._headers.get("X-N8N-API-KEY") == "mykey"


def test_no_auth_no_header():
    plat = N8nPlatform("http://localhost:5678")
    assert "X-N8N-API-KEY" not in plat._headers
    assert "Authorization" not in plat._headers


@pytest.mark.asyncio
async def test_health_check_ok():
    plat = N8nPlatform("http://localhost:5678")
    plat.get = AsyncMock(return_value=MagicMock(status_code=200))
    assert await plat.health_check() is True


@pytest.mark.asyncio
async def test_health_check_fail():
    plat = N8nPlatform("http://localhost:5678")
    plat.get = AsyncMock(return_value=MagicMock(status_code=500))
    assert await plat.health_check() is False


@pytest.mark.asyncio
async def test_enumerate_version_and_workflows():
    plat = N8nPlatform("http://localhost:5678")

    resp_version   = _json_resp(200, {"version": "1.47.0"})
    resp_workflows = _json_resp(200, {"data": [{"id": "wf1", "name": "My Flow"}], "nextCursor": None})
    resp_creds     = _json_resp(200, {"data": [{"id": "c1", "name": "My Cred", "type": "httpBasicAuth"}]})
    resp_404       = MagicMock(status_code=404)

    async def mock_get(path, **kw):
        return {
            "/api/v1/version":     resp_version,
            "/api/v1/workflows":   resp_workflows,
            "/api/v1/credentials": resp_creds,
        }.get(path, resp_404)

    plat.get = mock_get
    surface = await plat.enumerate()

    assert surface.version == "1.47.0"
    assert surface.auth_required is False
    assert len(surface.flows) == 1
    assert surface.flows[0]["name"] == "My Flow"
    assert len(surface.tools) == 1
    assert surface.tools[0]["type"] == "httpBasicAuth"


@pytest.mark.asyncio
async def test_enumerate_auth_required():
    plat = N8nPlatform("http://localhost:5678")

    resp_401 = MagicMock(status_code=401)
    resp_404 = MagicMock(status_code=404)

    async def mock_get(path, **kw):
        if path == "/api/v1/workflows":
            return resp_401
        return resp_404

    plat.get = mock_get
    surface = await plat.enumerate()

    assert surface.auth_required is True
    assert surface.flows == []
