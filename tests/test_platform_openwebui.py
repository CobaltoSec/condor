"""Tests for the Open WebUI platform adapter."""
import pytest
from unittest.mock import AsyncMock, MagicMock

from condor.platforms.openwebui import OpenWebUIPlatform


def _mock_response(status_code: int, json_data=None, text: str = ""):
    r = MagicMock()
    r.status_code = status_code
    r.json.return_value = json_data if json_data is not None else {}
    r.text = text
    return r


def test_platform_name():
    assert OpenWebUIPlatform.name == "openwebui"


def test_api_key_sets_bearer_header():
    plat = OpenWebUIPlatform("http://localhost:8080", api_key="tok123")
    assert plat._headers.get("Authorization") == "Bearer tok123"


def test_no_api_key_no_auth_header():
    plat = OpenWebUIPlatform("http://localhost:8080")
    assert "Authorization" not in plat._headers


@pytest.mark.asyncio
async def test_health_check_ok():
    plat = OpenWebUIPlatform("http://localhost:8080")
    plat._client = AsyncMock()
    plat._client.get = AsyncMock(return_value=_mock_response(200))
    assert await plat.health_check() is True


@pytest.mark.asyncio
async def test_health_check_500_returns_false():
    plat = OpenWebUIPlatform("http://localhost:8080")
    plat._client = AsyncMock()
    plat._client.get = AsyncMock(return_value=_mock_response(500))
    assert await plat.health_check() is False


@pytest.mark.asyncio
async def test_enumerate_detects_auth():
    plat = OpenWebUIPlatform("http://localhost:8080")
    plat._client = AsyncMock()
    plat._client.get = AsyncMock(return_value=_mock_response(401))
    surface = await plat.enumerate()
    assert surface.auth_required is True


@pytest.mark.asyncio
async def test_enumerate_functions_unauth_flag():
    plat = OpenWebUIPlatform("http://localhost:8080")
    plat._client = AsyncMock()

    def mock_get(path, **kwargs):
        if path == "/api/v1/models":
            return _mock_response(200, {"data": []})
        if path == "/api/v1/version":
            return _mock_response(200, {"version": "0.4.0"})
        if path == "/api/v1/tools":
            return _mock_response(200, [])
        if path == "/api/v1/functions":
            return _mock_response(200, [{"id": "fn1", "name": "exec"}])
        return _mock_response(404)

    plat._client.get = AsyncMock(side_effect=mock_get)
    surface = await plat.enumerate()
    assert surface.raw_info.get("functions_unauth") is True
    assert surface.version == "0.4.0"


@pytest.mark.asyncio
async def test_enumerate_populates_endpoints():
    plat = OpenWebUIPlatform("http://localhost:8080")
    plat._client = AsyncMock()

    def mock_get(path, **kwargs):
        if path in ("/api/v1/models", "/api/v1/tools"):
            return _mock_response(200, [])
        return _mock_response(404)

    plat._client.get = AsyncMock(side_effect=mock_get)
    surface = await plat.enumerate()
    assert "/api/v1/models" in surface.endpoints
    assert "/api/v1/tools" in surface.endpoints
