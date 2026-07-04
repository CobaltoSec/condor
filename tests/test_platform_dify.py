"""Tests for DifyPlatform adapter."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from condor.platforms.dify import DifyPlatform


def _mock_response(status_code: int, json_data=None, text: str = "") -> MagicMock:
    r = MagicMock(spec=httpx.Response)
    r.status_code = status_code
    r.text = text
    if json_data is not None:
        r.json = MagicMock(return_value=json_data)
    else:
        r.json = MagicMock(side_effect=Exception("no json"))
    return r


@pytest.fixture
def platform():
    return DifyPlatform("http://localhost:3000")


def test_platform_name(platform):
    assert platform.name == "dify"


@pytest.mark.asyncio
async def test_health_check_true_via_health(platform):
    platform._client = AsyncMock()
    platform._client.get = AsyncMock(return_value=_mock_response(200))
    result = await platform.health_check()
    assert result is True


@pytest.mark.asyncio
async def test_health_check_falls_back_to_ping(platform):
    platform._client = AsyncMock()
    responses = [
        _mock_response(500),   # /health fails
        _mock_response(200),   # /console/api/ping succeeds
    ]
    platform._client.get = AsyncMock(side_effect=responses)
    result = await platform.health_check()
    assert result is True


@pytest.mark.asyncio
async def test_health_check_false_when_all_fail(platform):
    platform._client = AsyncMock()
    platform._client.get = AsyncMock(side_effect=Exception("connection refused"))
    result = await platform.health_check()
    assert result is False


@pytest.mark.asyncio
async def test_enumerate_extracts_version(platform):
    platform._client = AsyncMock()

    def get_side_effect(path, **kwargs):
        if path == "/console/api/version":
            return _mock_response(200, {"version": "0.9.1"})
        return _mock_response(404)

    platform._client.get = AsyncMock(side_effect=get_side_effect)
    surface = await platform.enumerate()
    assert surface.version == "0.9.1"
    assert surface.platform == "dify"


@pytest.mark.asyncio
async def test_enumerate_extracts_flows_from_apps(platform):
    apps = [{"id": "app1", "name": "My App", "mode": "agent"}]
    platform._client = AsyncMock()

    def get_side_effect(path, **kwargs):
        if path == "/console/api/apps":
            return _mock_response(200, {"data": apps})
        return _mock_response(404)

    platform._client.get = AsyncMock(side_effect=get_side_effect)
    surface = await platform.enumerate()
    assert surface.flows == apps
    assert surface.auth_required is False


@pytest.mark.asyncio
async def test_enumerate_auth_required_on_401(platform):
    platform._client = AsyncMock()

    def get_side_effect(path, **kwargs):
        if path == "/console/api/apps":
            return _mock_response(401)
        return _mock_response(404)

    platform._client.get = AsyncMock(side_effect=get_side_effect)
    surface = await platform.enumerate()
    assert surface.auth_required is True
    assert surface.flows == []


@pytest.mark.asyncio
async def test_enumerate_extracts_tools(platform):
    providers = [{"name": "google_search"}, {"name": "calculator"}]
    platform._client = AsyncMock()

    def get_side_effect(path, **kwargs):
        if path == "/console/api/workspaces/current/tool-providers":
            return _mock_response(200, {"data": providers})
        return _mock_response(404)

    platform._client.get = AsyncMock(side_effect=get_side_effect)
    surface = await platform.enumerate()
    assert surface.tools == providers


@pytest.mark.asyncio
async def test_enumerate_accessible_endpoints(platform):
    platform._client = AsyncMock()

    def get_side_effect(path, **kwargs):
        if path == "/console/api/system-features":
            return _mock_response(200, {})
        return _mock_response(404)

    platform._client.get = AsyncMock(side_effect=get_side_effect)
    surface = await platform.enumerate()
    assert "/console/api/system-features" in surface.endpoints
