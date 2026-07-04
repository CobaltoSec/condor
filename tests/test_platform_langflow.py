"""Tests for the Langflow platform adapter."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from condor.platforms.langflow import LangflowPlatform


def _mock_response(status_code: int, json_data=None, text: str = ""):
    r = MagicMock()
    r.status_code = status_code
    r.json.return_value = json_data if json_data is not None else {}
    r.text = text
    return r


def test_platform_name():
    assert LangflowPlatform.name == "langflow"


@pytest.mark.asyncio
async def test_health_check_via_health_endpoint():
    plat = LangflowPlatform("http://localhost:7860")
    plat._client = AsyncMock()
    plat._client.get = AsyncMock(return_value=_mock_response(200))
    result = await plat.health_check()
    assert result is True
    plat._client.get.assert_called_once_with("/health")


@pytest.mark.asyncio
async def test_health_check_fallback_to_flows():
    plat = LangflowPlatform("http://localhost:7860")
    plat._client = AsyncMock()
    # /health returns 404, fallback to /api/v1/flows returns 200
    plat._client.get = AsyncMock(side_effect=[
        _mock_response(404),
        _mock_response(200),
    ])
    result = await plat.health_check()
    assert result is True


@pytest.mark.asyncio
async def test_health_check_returns_false_on_exception():
    plat = LangflowPlatform("http://localhost:7860")
    plat._client = AsyncMock()
    plat._client.get = AsyncMock(side_effect=Exception("connection refused"))
    result = await plat.health_check()
    assert result is False


@pytest.mark.asyncio
async def test_enumerate_extracts_version_flows_tools():
    plat = LangflowPlatform("http://localhost:7860")
    plat._client = AsyncMock()

    flows = [{"id": "abc", "name": "My Flow"}]
    components = [{"name": "Calculator", "type": "tool"}]

    def mock_get(path, **kwargs):
        if path == "/api/v1/version":
            return _mock_response(200, {"version": "1.2.3"})
        if path == "/api/v1/flows":
            return _mock_response(200, flows)
        if path == "/api/v1/components":
            return _mock_response(200, components)
        return _mock_response(404)

    plat._client.get = AsyncMock(side_effect=mock_get)
    surface = await plat.enumerate()

    assert surface.platform == "langflow"
    assert surface.version == "1.2.3"
    assert surface.flows == flows
    assert surface.tools == components
    assert surface.auth_required is False


@pytest.mark.asyncio
async def test_enumerate_auth_required_on_401():
    plat = LangflowPlatform("http://localhost:7860")
    plat._client = AsyncMock()

    def mock_get(path, **kwargs):
        if path == "/api/v1/version":
            return _mock_response(404)
        if path == "/api/v1/flows":
            return _mock_response(401)
        return _mock_response(404)

    plat._client.get = AsyncMock(side_effect=mock_get)
    surface = await plat.enumerate()

    assert surface.auth_required is True
    assert surface.flows == []


@pytest.mark.asyncio
async def test_enumerate_accessible_endpoints():
    plat = LangflowPlatform("http://localhost:7860")
    plat._client = AsyncMock()

    def mock_get(path, **kwargs):
        if path in ("/api/v1/flows", "/api/v1/variables"):
            return _mock_response(200, [])
        if path == "/api/v1/version":
            return _mock_response(200, {"version": "1.0.0"})
        if path == "/api/v1/components":
            return _mock_response(200, [])
        return _mock_response(404)

    plat._client.get = AsyncMock(side_effect=mock_get)
    surface = await plat.enumerate()

    assert "/api/v1/flows" in surface.endpoints
    assert "/api/v1/variables" in surface.endpoints
    assert "/api/v1/api_key" not in surface.endpoints
