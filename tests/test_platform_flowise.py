"""Tests for FlowisePlatform adapter."""
import base64
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from condor.platforms.flowise import FlowisePlatform, _SENSITIVE_ENDPOINTS


def _json_resp(status: int, data) -> MagicMock:
    r = MagicMock(status_code=status, text=json.dumps(data), content=json.dumps(data).encode())
    r.json.return_value = data
    return r


def _resp(status: int) -> MagicMock:
    return MagicMock(status_code=status)


# ---------------------------------------------------------------------------
# Construction / header tests
# ---------------------------------------------------------------------------

def test_platform_name():
    assert FlowisePlatform("http://localhost:3000").name == "flowise"


def test_api_key_auth():
    plat = FlowisePlatform("http://localhost:3000", api_key="test-key")
    assert plat._headers.get("Authorization") == "Bearer test-key"


def test_basic_auth():
    plat = FlowisePlatform("http://localhost:3000", username="admin", password="secret")
    expected = base64.b64encode(b"admin:secret").decode()
    assert plat._headers.get("Authorization") == f"Basic {expected}"


def test_no_auth_no_header():
    plat = FlowisePlatform("http://localhost:3000")
    assert "Authorization" not in plat._headers


# ---------------------------------------------------------------------------
# health_check
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_health_check_ok():
    plat = FlowisePlatform("http://localhost:3000")
    plat.get = AsyncMock(return_value=_resp(200))
    assert await plat.health_check() is True


@pytest.mark.asyncio
async def test_health_check_401():
    """401 means the server is live with auth enabled — status < 500 → True."""
    plat = FlowisePlatform("http://localhost:3000")
    plat.get = AsyncMock(return_value=_resp(401))
    assert await plat.health_check() is True


@pytest.mark.asyncio
async def test_health_check_fail():
    """Connection-level exception → False."""
    plat = FlowisePlatform("http://localhost:3000")
    plat.get = AsyncMock(side_effect=Exception("connection refused"))
    assert await plat.health_check() is False


# ---------------------------------------------------------------------------
# enumerate
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_enumerate_with_flows():
    """Two chatflows → surface.flows populated, base_url and platform set."""
    plat = FlowisePlatform("http://localhost:3000")

    flows = [
        {"id": "flow-1", "name": "My Chatbot"},
        {"id": "flow-2", "name": "RAG Pipeline"},
    ]

    async def mock_get(path, **kw):
        if path == "/api/v1/chatflows":
            return _json_resp(200, flows)
        return _resp(404)

    plat.get = mock_get
    surface = await plat.enumerate()

    assert surface.platform == "flowise"
    assert surface.base_url == "http://localhost:3000"
    assert len(surface.flows) == 2
    assert surface.auth_required is False


@pytest.mark.asyncio
async def test_enumerate_empty():
    """Empty chatflows list → surface.flows == []."""
    plat = FlowisePlatform("http://localhost:3000")

    async def mock_get(path, **kw):
        if path == "/api/v1/chatflows":
            return _json_resp(200, [])
        return _resp(404)

    plat.get = mock_get
    surface = await plat.enumerate()

    assert surface.flows == []
    assert surface.auth_required is False


@pytest.mark.asyncio
async def test_enumerate_auth_required():
    """401 on chatflows → surface.auth_required = True, flows stays empty."""
    plat = FlowisePlatform("http://localhost:3000")

    async def mock_get(path, **kw):
        if path == "/api/v1/chatflows":
            return _resp(401)
        return _resp(404)

    plat.get = mock_get
    surface = await plat.enumerate()

    assert surface.auth_required is True
    assert surface.flows == []


@pytest.mark.asyncio
async def test_enumerate_sensitive_endpoints_in_surface():
    """Endpoints that respond with non-404 are collected in surface.endpoints."""
    plat = FlowisePlatform("http://localhost:3000")

    accessible = {"/api/v1/chatflows", "/api/v1/credentials", "/api/v1/variables"}

    async def mock_get(path, **kw):
        if path in accessible:
            return _json_resp(200, [])
        return _resp(404)

    plat.get = mock_get
    surface = await plat.enumerate()

    for ep in accessible:
        assert ep in surface.endpoints
    # Endpoints that returned 404 must not appear
    assert "/api/v1/apikey" not in surface.endpoints
    assert "/api/v1/stats" not in surface.endpoints


@pytest.mark.asyncio
async def test_enumerate_flows_extracts_ids():
    """Flow dict IDs from chatflows response are preserved in surface.flows."""
    plat = FlowisePlatform("http://localhost:3000")

    flows = [
        {"id": "abc-123", "name": "Agent Flow 1"},
        {"id": "def-456", "name": "Agent Flow 2"},
    ]

    async def mock_get(path, **kw):
        if path == "/api/v1/chatflows":
            return _json_resp(200, flows)
        return _resp(404)

    plat.get = mock_get
    surface = await plat.enumerate()

    ids = [f["id"] for f in surface.flows]
    assert "abc-123" in ids
    assert "def-456" in ids


@pytest.mark.asyncio
async def test_enumerate_version_detected():
    """Version from /api/v1/version is stored in surface.version."""
    plat = FlowisePlatform("http://localhost:3000")

    async def mock_get(path, **kw):
        if path == "/api/v1/version":
            return _json_resp(200, {"version": "2.1.3"})
        if path == "/api/v1/chatflows":
            return _json_resp(200, [])
        return _resp(404)

    plat.get = mock_get
    surface = await plat.enumerate()

    assert surface.version == "2.1.3"


@pytest.mark.asyncio
async def test_enumerate_tools_populated():
    """Tools returned by /api/v1/tools are stored in surface.tools."""
    plat = FlowisePlatform("http://localhost:3000")

    tools = [{"id": "t1", "name": "Calculator"}, {"id": "t2", "name": "WebBrowser"}]

    async def mock_get(path, **kw):
        if path == "/api/v1/chatflows":
            return _json_resp(200, [])
        if path == "/api/v1/tools":
            return _json_resp(200, tools)
        return _resp(404)

    plat.get = mock_get
    surface = await plat.enumerate()

    assert len(surface.tools) == 2
    assert surface.tools[0]["name"] == "Calculator"
