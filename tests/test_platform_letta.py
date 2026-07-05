"""Tests for the Letta platform adapter."""
import pytest
from unittest.mock import AsyncMock, MagicMock

from condor.platforms.letta import LettaPlatform


def _mock_response(status_code: int, json_data=None, text: str = ""):
    r = MagicMock()
    r.status_code = status_code
    r.json.return_value = json_data if json_data is not None else {}
    r.text = text
    return r


def test_platform_name():
    assert LettaPlatform.name == "letta"


def test_api_key_sets_bearer_header():
    plat = LettaPlatform("http://localhost:8283", api_key="letta-key")
    assert plat._headers.get("Authorization") == "Bearer letta-key"


@pytest.mark.asyncio
async def test_health_check_ok():
    plat = LettaPlatform("http://localhost:8283")
    plat._client = AsyncMock()
    plat._client.get = AsyncMock(return_value=_mock_response(200))
    assert await plat.health_check() is True


@pytest.mark.asyncio
async def test_health_check_fallback():
    plat = LettaPlatform("http://localhost:8283")
    plat._client = AsyncMock()
    plat._client.get = AsyncMock(side_effect=[
        Exception("no health"),
        _mock_response(200, []),
    ])
    assert await plat.health_check() is True


@pytest.mark.asyncio
async def test_enumerate_agents_and_tools():
    plat = LettaPlatform("http://localhost:8283")
    plat._client = AsyncMock()

    agents = [{"id": "agent-1", "name": "MyAgent"}]
    tools = [{"id": "tool-1", "name": "search"}]

    def mock_get(path, **kwargs):
        if path == "/v1/health":
            return _mock_response(200, {"version": "0.5.0"})
        if path == "/v1/agents":
            return _mock_response(200, agents)
        if path == "/v1/tools":
            return _mock_response(200, tools)
        if path == "/v1/sources":
            return _mock_response(200, [])
        return _mock_response(404)

    plat._client.get = AsyncMock(side_effect=mock_get)
    surface = await plat.enumerate()

    assert surface.version == "0.5.0"
    assert surface.flows == agents
    assert surface.tools == tools
    assert surface.auth_required is False


@pytest.mark.asyncio
async def test_enumerate_per_agent_memory_endpoints():
    plat = LettaPlatform("http://localhost:8283")
    plat._client = AsyncMock()

    def mock_get(path, **kwargs):
        if path == "/v1/agents":
            return _mock_response(200, [{"id": "a1"}, {"id": "a2"}])
        return _mock_response(404)

    plat._client.get = AsyncMock(side_effect=mock_get)
    surface = await plat.enumerate()

    assert "/v1/agents/a1/memory" in surface.endpoints
    assert "/v1/agents/a2/memory" in surface.endpoints


@pytest.mark.asyncio
async def test_enumerate_auth_on_403():
    plat = LettaPlatform("http://localhost:8283")
    plat._client = AsyncMock()

    def mock_get(path, **kwargs):
        if path == "/v1/agents":
            return _mock_response(403)
        return _mock_response(404)

    plat._client.get = AsyncMock(side_effect=mock_get)
    surface = await plat.enumerate()
    assert surface.auth_required is True


@pytest.mark.asyncio
async def test_enumerate_sources_in_raw_info():
    plat = LettaPlatform("http://localhost:8283")
    plat._client = AsyncMock()

    def mock_get(path, **kwargs):
        if path == "/v1/sources":
            return _mock_response(200, [{"id": "s1"}])
        return _mock_response(404)

    plat._client.get = AsyncMock(side_effect=mock_get)
    surface = await plat.enumerate()
    assert "sources" in surface.raw_info
