"""Tests for the Hayhooks platform adapter."""
import pytest
from unittest.mock import AsyncMock, MagicMock

from condor.platforms.hayhooks import HayhooksPlatform


def _mock_response(status_code: int, json_data=None, text: str = ""):
    r = MagicMock()
    r.status_code = status_code
    r.json.return_value = json_data if json_data is not None else {}
    r.text = text
    return r


def test_platform_name():
    assert HayhooksPlatform.name == "hayhooks"


@pytest.mark.asyncio
async def test_health_check_ok():
    plat = HayhooksPlatform("http://localhost:1416")
    plat._client = AsyncMock()
    plat._client.get = AsyncMock(return_value=_mock_response(200))
    assert await plat.health_check() is True


@pytest.mark.asyncio
async def test_health_check_failure():
    plat = HayhooksPlatform("http://localhost:1416")
    plat._client = AsyncMock()
    plat._client.get = AsyncMock(side_effect=Exception("refused"))
    assert await plat.health_check() is False


@pytest.mark.asyncio
async def test_enumerate_extracts_version():
    plat = HayhooksPlatform("http://localhost:1416")
    plat._client = AsyncMock()

    def mock_get(path, **kwargs):
        if path == "/status":
            return _mock_response(200, {"version": "0.10.0"})
        return _mock_response(404)

    plat._client.get = AsyncMock(side_effect=mock_get)
    surface = await plat.enumerate()
    assert surface.version == "0.10.0"


@pytest.mark.asyncio
async def test_enumerate_pipelines_as_strings_normalized():
    plat = HayhooksPlatform("http://localhost:1416")
    plat._client = AsyncMock()

    def mock_get(path, **kwargs):
        if path == "/status":
            return _mock_response(200, {})
        if path == "/pipelines":
            return _mock_response(200, ["rag_pipeline", "qa_pipeline"])
        return _mock_response(404)

    plat._client.get = AsyncMock(side_effect=mock_get)
    surface = await plat.enumerate()
    assert len(surface.flows) == 2
    assert surface.flows[0] == {"id": "rag_pipeline", "name": "rag_pipeline"}


@pytest.mark.asyncio
async def test_enumerate_openapi_paths():
    plat = HayhooksPlatform("http://localhost:1416")
    plat._client = AsyncMock()

    def mock_get(path, **kwargs):
        if path == "/status":
            return _mock_response(200, {})
        if path == "/pipelines":
            return _mock_response(404)
        if path == "/openapi.json":
            return _mock_response(200, {"paths": {"/pipelines": {}, "/pipeline/run/test": {}}})
        return _mock_response(404)

    plat._client.get = AsyncMock(side_effect=mock_get)
    surface = await plat.enumerate()
    assert "/pipelines" in surface.endpoints
    assert "/pipeline/run/test" in surface.endpoints


@pytest.mark.asyncio
async def test_enumerate_auth_detected_on_401():
    plat = HayhooksPlatform("http://localhost:1416")
    plat._client = AsyncMock()

    def mock_get(path, **kwargs):
        if path == "/status":
            return _mock_response(200, {})
        if path == "/pipelines":
            return _mock_response(401)
        return _mock_response(404)

    plat._client.get = AsyncMock(side_effect=mock_get)
    surface = await plat.enumerate()
    assert surface.auth_required is True
