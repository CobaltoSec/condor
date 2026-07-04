"""Tests for LangGraphPlatform adapter."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from condor.platforms.langgraph import LangGraphPlatform


def _mock_response(status_code: int, json_data=None) -> MagicMock:
    r = MagicMock()
    r.status_code = status_code
    r.json = MagicMock(return_value=json_data if json_data is not None else {})
    return r


def _platform() -> LangGraphPlatform:
    return LangGraphPlatform("http://localhost:8123")


async def test_health_check_ok():
    plat = _platform()
    plat.get = AsyncMock(return_value=_mock_response(200))
    result = await plat.health_check()
    assert result is True
    plat.get.assert_called_once_with("/ok")


async def test_health_check_fail():
    plat = _platform()
    plat.get = AsyncMock(return_value=_mock_response(503))
    result = await plat.health_check()
    assert result is False


async def test_health_check_exception():
    plat = _platform()
    plat.get = AsyncMock(side_effect=Exception("connection refused"))
    result = await plat.health_check()
    assert result is False


async def test_enumerate_with_assistants():
    plat = _platform()
    assistants = [{"assistant_id": "a1", "name": "MyAgent"}, {"assistant_id": "a2", "name": "Bot"}]

    async def _get(path, **kw):
        if path == "/assistants":
            return _mock_response(200, assistants)
        return _mock_response(404)

    plat.get = _get
    surface = await plat.enumerate()
    assert surface.flows == assistants
    assert surface.auth_required is False


async def test_enumerate_store_accessible():
    plat = _platform()

    async def _get(path, **kw):
        if path == "/store/items":
            return _mock_response(200, [])
        return _mock_response(404)

    plat.get = _get
    surface = await plat.enumerate()
    assert surface.raw_info.get("store_accessible") is True


async def test_enumerate_runs_accessible():
    plat = _platform()

    async def _get(path, **kw):
        if path == "/runs":
            return _mock_response(200, [])
        return _mock_response(404)

    plat.get = _get
    surface = await plat.enumerate()
    assert surface.raw_info.get("runs_accessible") is True


async def test_enumerate_auth_required():
    plat = _platform()

    async def _get(path, **kw):
        return _mock_response(401)

    plat.get = _get
    surface = await plat.enumerate()
    assert surface.auth_required is True


async def test_enumerate_empty_assistants():
    plat = _platform()

    async def _get(path, **kw):
        if path == "/assistants":
            return _mock_response(200, [])
        return _mock_response(404)

    plat.get = _get
    surface = await plat.enumerate()
    assert surface.flows == []
    assert surface.auth_required is False


async def test_enumerate_threads_count():
    plat = _platform()
    threads = [{"thread_id": "t1"}, {"thread_id": "t2"}, {"thread_id": "t3"}]

    async def _get(path, **kw):
        if path == "/threads":
            return _mock_response(200, threads)
        return _mock_response(404)

    plat.get = _get
    surface = await plat.enumerate()
    assert surface.raw_info.get("threads") == 3


async def test_enumerate_partial_auth_mixed():
    plat = _platform()

    async def _get(path, **kw):
        if path == "/assistants":
            return _mock_response(200, [{"assistant_id": "a1"}])
        if path == "/store/items":
            return _mock_response(403)
        return _mock_response(404)

    plat.get = _get
    surface = await plat.enumerate()
    assert surface.auth_required is True
    assert len(surface.flows) == 1


async def test_enumerate_endpoint_exception_handled():
    plat = _platform()
    call_count = 0

    async def _get(path, **kw):
        nonlocal call_count
        call_count += 1
        if path == "/assistants":
            raise Exception("timeout")
        return _mock_response(200, [])

    plat.get = _get
    surface = await plat.enumerate()
    assert call_count >= 2
    assert surface.flows == []


async def test_api_key_sets_header():
    plat = LangGraphPlatform("http://localhost:8123", api_key="secret-key")
    assert plat._headers.get("x-api-key") == "secret-key"
