"""Tests for OpenAI-compatible platform adapter."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from condor.platforms.openai_compat import OpenAICompatPlatform


def _mock_response(status: int, json_data=None, headers=None):
    r = MagicMock()
    r.status_code = status
    r.headers = headers or {}
    if json_data is not None:
        r.json = MagicMock(return_value=json_data)
    else:
        r.json = MagicMock(side_effect=Exception("no body"))
    return r


def _make_platform(api_key=None):
    p = OpenAICompatPlatform("http://localhost:8080", api_key=api_key)
    p._client = MagicMock()
    return p


async def test_health_check_ok():
    p = _make_platform()
    p.get = AsyncMock(return_value=_mock_response(200, {"data": []}))
    assert await p.health_check() is True


async def test_health_check_fail():
    p = _make_platform()
    p.get = AsyncMock(return_value=_mock_response(401))
    assert await p.health_check() is False


async def test_health_check_exception():
    p = _make_platform()
    p.get = AsyncMock(side_effect=Exception("connection refused"))
    assert await p.health_check() is False


async def test_enumerate_models():
    p = _make_platform()
    models_resp = _mock_response(200, {"data": [{"id": "gpt-4"}, {"id": "llama-3"}]})

    async def _get(path, **kw):
        if path == "/v1/models":
            return models_resp
        return _mock_response(404)

    p.get = _get
    surface = await p.enumerate()
    assert len(surface.flows) == 2
    assert surface.flows[0]["id"] == "gpt-4"
    assert surface.auth_required is False


async def test_enumerate_assistants_accessible():
    p = _make_platform()
    asst_resp = _mock_response(200, {"data": [{"id": "asst_1"}, {"id": "asst_2"}]})

    async def _get(path, **kw):
        if path == "/v1/models":
            return _mock_response(200, {"data": []})
        if path == "/v1/assistants":
            return asst_resp
        return _mock_response(404)

    p.get = _get
    surface = await p.enumerate()
    assert surface.raw_info.get("v1_assistants_accessible") is True
    assert surface.raw_info.get("v1_assistants_count") == 2
    assert "/v1/assistants" in surface.endpoints


async def test_enumerate_vector_stores_accessible():
    p = _make_platform()

    async def _get(path, **kw):
        if path == "/v1/models":
            return _mock_response(200, {"data": []})
        if path == "/v1/vector_stores":
            return _mock_response(200, {"data": []})
        return _mock_response(404)

    p.get = _get
    surface = await p.enumerate()
    assert surface.raw_info.get("v1_vector_stores_accessible") is True
    assert "/v1/vector_stores" in surface.endpoints


async def test_enumerate_auth_required():
    p = _make_platform()
    p.get = AsyncMock(return_value=_mock_response(401))
    surface = await p.enumerate()
    assert surface.auth_required is True


async def test_api_key_sets_header():
    p = OpenAICompatPlatform("http://localhost:8080", api_key="sk-test-key")
    assert p._headers.get("Authorization") == "Bearer sk-test-key"


async def test_enumerate_version_from_header():
    p = _make_platform()
    models_resp = _mock_response(200, {"data": []}, headers={"x-openai-version": "1.2.3"})

    async def _get(path, **kw):
        if path == "/v1/models":
            return models_resp
        return _mock_response(404)

    p.get = _get
    surface = await p.enumerate()
    assert surface.version == "1.2.3"


async def test_enumerate_handles_endpoint_failure_gracefully():
    p = _make_platform()

    async def _get(path, **kw):
        if path == "/v1/models":
            return _mock_response(200, {"data": [{"id": "model-1"}]})
        raise Exception("network error")

    p.get = _get
    surface = await p.enumerate()
    assert len(surface.flows) == 1
    assert surface.endpoints == []
