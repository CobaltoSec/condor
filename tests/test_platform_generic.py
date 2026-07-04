"""Tests for GenericPlatform."""
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from condor.platforms.generic import GenericPlatform


def _mock_client(responses: dict) -> MagicMock:
    client = MagicMock()

    async def _get(path, **kw):
        if path in responses:
            return responses[path]
        return MagicMock(status_code=404, text="not found")

    async def _post(path, **kw):
        key = f"POST:{path}"
        if key in responses:
            return responses[key]
        return MagicMock(status_code=404, text="not found")

    client.get = _get
    client.post = _post
    return client


def _resp(status: int, body: str = "") -> MagicMock:
    return MagicMock(status_code=status, text=body)


@pytest.mark.asyncio
async def test_openapi_spec_discovery():
    spec = {"openapi": "3.0.0", "paths": {"/api/v1/agents": {}, "/api/v1/tools": {}}}
    plat = GenericPlatform("http://localhost:8080")
    plat._client = _mock_client({
        "/openapi.json": _resp(200, json.dumps(spec)),
    })
    surface = await plat.enumerate()
    assert "/api/v1/agents" in surface.endpoints
    assert "/api/v1/tools" in surface.endpoints
    assert surface.raw_info.get("openapi_spec_found") is True
    assert surface.raw_info.get("openapi_path") == "/openapi.json"


@pytest.mark.asyncio
async def test_openapi_fallback_to_swagger():
    spec = {"swagger": "2.0", "paths": {"/api/predict": {}, "/api/status": {}}}
    plat = GenericPlatform("http://localhost:8080")
    plat._client = _mock_client({
        "/swagger.json": _resp(200, json.dumps(spec)),
    })
    surface = await plat.enumerate()
    assert "/api/predict" in surface.endpoints
    assert "/api/status" in surface.endpoints
    assert surface.raw_info.get("openapi_spec_found") is True
    assert surface.raw_info.get("openapi_path") == "/swagger.json"


@pytest.mark.asyncio
async def test_openapi_not_found():
    plat = GenericPlatform("http://localhost:8080")
    plat._client = _mock_client({})
    surface = await plat.enumerate()
    assert surface.raw_info.get("openapi_spec_found") is None
    assert surface.raw_info.get("openapi_path") is None


@pytest.mark.asyncio
async def test_openapi_invalid_json_skipped():
    plat = GenericPlatform("http://localhost:8080")
    plat._client = _mock_client({
        "/openapi.json": _resp(200, "not-json{{{"),
    })
    surface = await plat.enumerate()
    assert surface.raw_info.get("openapi_spec_found") is None


@pytest.mark.asyncio
async def test_openapi_deduplicates_existing_endpoints():
    spec = {"paths": {"/api/v1/agents": {}, "/api/v1/tools": {}}}
    plat = GenericPlatform("http://localhost:8080")
    plat._client = _mock_client({
        "/api/v1/agents": _resp(200),
        "/openapi.json": _resp(200, json.dumps(spec)),
    })
    surface = await plat.enumerate()
    assert surface.endpoints.count("/api/v1/agents") == 1


@pytest.mark.asyncio
async def test_graphql_discovery():
    gql_body = json.dumps({"data": {"__typename": "Query"}})
    plat = GenericPlatform("http://localhost:8080")
    plat._client = _mock_client({
        "POST:/graphql": _resp(200, gql_body),
    })
    surface = await plat.enumerate()
    assert "/graphql" in surface.endpoints
    assert surface.raw_info.get("graphql_exposed") is True


@pytest.mark.asyncio
async def test_graphql_not_exposed():
    plat = GenericPlatform("http://localhost:8080")
    plat._client = _mock_client({})
    surface = await plat.enumerate()
    assert surface.raw_info.get("graphql_exposed") is None
    assert "/graphql" not in surface.endpoints


@pytest.mark.asyncio
async def test_graphql_invalid_response_ignored():
    plat = GenericPlatform("http://localhost:8080")
    plat._client = _mock_client({
        "POST:/graphql": _resp(200, "plain text no json"),
    })
    surface = await plat.enumerate()
    assert surface.raw_info.get("graphql_exposed") is None


@pytest.mark.asyncio
async def test_health_check_returns_true_on_200():
    plat = GenericPlatform("http://localhost:8080")
    plat._client = _mock_client({"/health": _resp(200)})
    assert await plat.health_check() is True


@pytest.mark.asyncio
async def test_health_check_returns_false_when_all_fail():
    plat = GenericPlatform("http://localhost:8080")
    client = MagicMock()

    async def _raise(*a, **kw):
        raise ConnectionError("refused")

    client.get = _raise
    plat._client = client
    assert await plat.health_check() is False


@pytest.mark.asyncio
async def test_auth_required_detected():
    plat = GenericPlatform("http://localhost:8080")
    plat._client = _mock_client({"/api/v1/chatflows": _resp(401)})
    surface = await plat.enumerate()
    assert surface.auth_required is True
