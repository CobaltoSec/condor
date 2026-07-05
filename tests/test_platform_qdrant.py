"""Tests for the Qdrant platform adapter."""
import pytest
from unittest.mock import AsyncMock, MagicMock

from condor.platforms.qdrant import QdrantPlatform


def _mock_response(status_code: int, json_data=None, text: str = ""):
    r = MagicMock()
    r.status_code = status_code
    r.json.return_value = json_data if json_data is not None else {}
    r.text = text
    return r


def test_platform_name():
    assert QdrantPlatform.name == "qdrant"


def test_api_key_uses_native_header():
    plat = QdrantPlatform("http://localhost:6333", api_key="qdrant-secret")
    assert plat._headers.get("api-key") == "qdrant-secret"
    assert "Authorization" not in plat._headers


@pytest.mark.asyncio
async def test_health_check_healthz():
    plat = QdrantPlatform("http://localhost:6333")
    plat._client = AsyncMock()
    plat._client.get = AsyncMock(return_value=_mock_response(200))
    assert await plat.health_check() is True


@pytest.mark.asyncio
async def test_health_check_fallback_collections():
    plat = QdrantPlatform("http://localhost:6333")
    plat._client = AsyncMock()
    plat._client.get = AsyncMock(side_effect=[
        Exception("refused"),
        _mock_response(200, {"result": {"collections": []}}),
    ])
    assert await plat.health_check() is True


@pytest.mark.asyncio
async def test_enumerate_collections():
    plat = QdrantPlatform("http://localhost:6333")
    plat._client = AsyncMock()

    collections = [{"name": "docs"}, {"name": "embeddings"}]

    def mock_get(path, **kwargs):
        if path == "/collections":
            return _mock_response(200, {"result": {"collections": collections}})
        if path == "/telemetry":
            return _mock_response(200, {"result": {"version": "1.9.0"}})
        return _mock_response(404)

    plat._client.get = AsyncMock(side_effect=mock_get)
    surface = await plat.enumerate()

    assert surface.raw_info["collections"] == collections
    assert surface.version == "1.9.0"
    assert surface.auth_required is False


@pytest.mark.asyncio
async def test_enumerate_auth_on_401():
    plat = QdrantPlatform("http://localhost:6333")
    plat._client = AsyncMock()

    def mock_get(path, **kwargs):
        if path == "/collections":
            return _mock_response(401)
        return _mock_response(404)

    plat._client.get = AsyncMock(side_effect=mock_get)
    surface = await plat.enumerate()
    assert surface.auth_required is True


@pytest.mark.asyncio
async def test_enumerate_endpoints_populated():
    plat = QdrantPlatform("http://localhost:6333")
    plat._client = AsyncMock()

    def mock_get(path, **kwargs):
        if path in ("/collections", "/healthz"):
            return _mock_response(200, {"result": {"collections": []}})
        return _mock_response(404)

    plat._client.get = AsyncMock(side_effect=mock_get)
    surface = await plat.enumerate()
    assert "/collections" in surface.endpoints
    assert "/healthz" in surface.endpoints


@pytest.mark.asyncio
async def test_enumerate_no_flows_or_tools():
    plat = QdrantPlatform("http://localhost:6333")
    plat._client = AsyncMock()
    plat._client.get = AsyncMock(return_value=_mock_response(404))
    surface = await plat.enumerate()
    assert surface.flows == []
    assert surface.tools == []
