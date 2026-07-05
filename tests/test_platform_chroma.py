"""Tests for the Chroma platform adapter."""
import pytest
from unittest.mock import AsyncMock, MagicMock

from condor.platforms.chroma import ChromaPlatform


def _mock_response(status_code: int, json_data=None, text: str = ""):
    r = MagicMock()
    r.status_code = status_code
    r.json.return_value = json_data if json_data is not None else {}
    r.text = text
    return r


def test_platform_name():
    assert ChromaPlatform.name == "chroma"


@pytest.mark.asyncio
async def test_health_check_heartbeat():
    plat = ChromaPlatform("http://localhost:8000")
    plat._client = AsyncMock()
    plat._client.get = AsyncMock(return_value=_mock_response(200))
    assert await plat.health_check() is True


@pytest.mark.asyncio
async def test_health_check_failure():
    plat = ChromaPlatform("http://localhost:8000")
    plat._client = AsyncMock()
    plat._client.get = AsyncMock(side_effect=Exception("refused"))
    assert await plat.health_check() is False


@pytest.mark.asyncio
async def test_enumerate_version_bare_string():
    plat = ChromaPlatform("http://localhost:8000")
    plat._client = AsyncMock()

    def mock_get(path, **kwargs):
        if path == "/api/v1/version":
            return _mock_response(200, text='"0.5.11"')
        return _mock_response(404)

    plat._client.get = AsyncMock(side_effect=mock_get)
    surface = await plat.enumerate()
    assert surface.version == "0.5.11"


@pytest.mark.asyncio
async def test_enumerate_collections():
    plat = ChromaPlatform("http://localhost:8000")
    plat._client = AsyncMock()

    def mock_get(path, **kwargs):
        if path == "/api/v1/version":
            return _mock_response(200, text='"0.5.11"')
        if path == "/api/v1/collections":
            return _mock_response(200, [{"name": "docs"}, {"name": "facts"}])
        return _mock_response(404)

    plat._client.get = AsyncMock(side_effect=mock_get)
    surface = await plat.enumerate()
    assert surface.raw_info["collections"] == ["docs", "facts"]
    assert surface.auth_required is False


@pytest.mark.asyncio
async def test_enumerate_per_collection_endpoints():
    plat = ChromaPlatform("http://localhost:8000")
    plat._client = AsyncMock()

    def mock_get(path, **kwargs):
        if path == "/api/v1/collections":
            return _mock_response(200, [{"name": "mydb"}])
        return _mock_response(404)

    plat._client.get = AsyncMock(side_effect=mock_get)
    surface = await plat.enumerate()
    assert "/api/v1/collections/mydb" in surface.endpoints


@pytest.mark.asyncio
async def test_enumerate_auth_on_401():
    plat = ChromaPlatform("http://localhost:8000")
    plat._client = AsyncMock()

    def mock_get(path, **kwargs):
        if path == "/api/v1/collections":
            return _mock_response(401)
        return _mock_response(404)

    plat._client.get = AsyncMock(side_effect=mock_get)
    surface = await plat.enumerate()
    assert surface.auth_required is True
