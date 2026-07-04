"""Tests for OllamaPlatform."""
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from condor.platforms.ollama import OllamaPlatform


def _mock_response(status: int, body: dict | str = "") -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.headers = {}
    if isinstance(body, dict):
        r.json = lambda: body
        r.text = json.dumps(body)
    else:
        r.json = lambda: {}
        r.text = body
    return r


def _make_platform(api_key: str | None = None) -> OllamaPlatform:
    return OllamaPlatform("http://localhost:11434", api_key=api_key)


async def _enter(plat: OllamaPlatform, get_map: dict, post_map: dict | None = None):
    post_map = post_map or {}

    async def _get(path, **kw):
        return get_map.get(path, _mock_response(404))

    async def _post(path, **kw):
        return post_map.get(path, _mock_response(404))

    plat.get = _get
    plat.post = _post
    return plat


async def test_health_check_ok():
    plat = _make_platform()
    body = {"models": [{"name": "llama3"}]}
    await _enter(plat, {"/api/tags": _mock_response(200, body)})
    assert await plat.health_check() is True


async def test_health_check_fail():
    plat = _make_platform()
    await _enter(plat, {"/api/tags": _mock_response(500)})
    assert await plat.health_check() is False


async def test_enumerate_models_populated():
    plat = _make_platform()
    tags_body = {
        "models": [
            {"name": "llama3:latest"},
            {"name": "mistral:7b"},
        ]
    }
    await _enter(
        plat,
        {"/api/tags": _mock_response(200, tags_body), "/api/ps": _mock_response(200, {"models": []})},
        {ep: _mock_response(200) for ep in ["/api/pull", "/api/create", "/api/push"]},
    )
    surface = await plat.enumerate()
    assert len(surface.flows) == 2
    ids = {f["id"] for f in surface.flows}
    assert "llama3:latest" in ids
    assert "mistral:7b" in ids


async def test_enumerate_running_models():
    plat = _make_platform()
    running = [{"name": "llama3:latest", "size_vram": 4000000000}]
    await _enter(
        plat,
        {
            "/api/tags": _mock_response(200, {"models": []}),
            "/api/ps": _mock_response(200, {"models": running}),
        },
        {ep: _mock_response(401) for ep in ["/api/pull", "/api/create", "/api/push"]},
    )
    surface = await plat.enumerate()
    assert surface.raw_info.get("running_models") == running


async def test_enumerate_write_endpoints_open():
    plat = _make_platform()
    await _enter(
        plat,
        {"/api/tags": _mock_response(200, {"models": []}), "/api/ps": _mock_response(404)},
        {"/api/pull": _mock_response(400), "/api/create": _mock_response(400), "/api/push": _mock_response(400)},
    )
    surface = await plat.enumerate()
    open_eps = surface.raw_info.get("write_endpoints_open", [])
    assert "/api/pull" in open_eps
    assert "/api/create" in open_eps


async def test_enumerate_write_endpoints_blocked():
    plat = _make_platform()
    await _enter(
        plat,
        {"/api/tags": _mock_response(200, {"models": []}), "/api/ps": _mock_response(404)},
        {ep: _mock_response(401) for ep in ["/api/pull", "/api/create", "/api/push"]},
    )
    surface = await plat.enumerate()
    assert surface.raw_info.get("write_endpoints_open") == []


async def test_enumerate_no_models():
    plat = _make_platform()
    await _enter(
        plat,
        {"/api/tags": _mock_response(200, {"models": []}), "/api/ps": _mock_response(200, {"models": []})},
        {ep: _mock_response(401) for ep in ["/api/pull", "/api/create", "/api/push"]},
    )
    surface = await plat.enumerate()
    assert surface.flows == []


async def test_auth_required_when_api_key_set():
    plat = _make_platform(api_key="secret")
    await _enter(
        plat,
        {"/api/tags": _mock_response(200, {"models": []}), "/api/ps": _mock_response(404)},
        {ep: _mock_response(401) for ep in ["/api/pull", "/api/create", "/api/push"]},
    )
    surface = await plat.enumerate()
    assert surface.auth_required is True


async def test_version_from_header():
    plat = _make_platform()
    tags_resp = _mock_response(200, {"models": []})
    tags_resp.headers = {"X-Ollama-Version": "0.3.6"}
    await _enter(
        plat,
        {"/api/tags": tags_resp, "/api/ps": _mock_response(404)},
        {ep: _mock_response(401) for ep in ["/api/pull", "/api/create", "/api/push"]},
    )
    surface = await plat.enumerate()
    assert surface.version == "0.3.6"
