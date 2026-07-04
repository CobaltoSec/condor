"""Tests for ASI10 RogueAgentsModule."""
import pytest
from unittest.mock import MagicMock

from condor.core.models import AgentSurface, OWASPCategory, Severity
from condor.modules.asi10_rogue import RogueAgentsModule


def _surface(**kwargs) -> AgentSurface:
    defaults = {"platform": "flowise", "base_url": "http://localhost:3000"}
    defaults.update(kwargs)
    return AgentSurface(**defaults)


def _mock_platform(responses: dict | None = None) -> MagicMock:
    plat = MagicMock()
    resp_404 = MagicMock(status_code=404, text="", content=b"")
    resp_404.headers = {}

    async def _post(path, **kw):
        if responses and path in responses:
            return responses[path]
        return resp_404

    plat.post = _post
    return plat


def _json_resp(status: int, data) -> MagicMock:
    import json as _json
    body = _json.dumps(data)
    r = MagicMock(status_code=status, text=body, content=body.encode())
    r.headers = {"content-type": "application/json"}
    r.json.return_value = data
    return r


def test_module_metadata():
    m = RogueAgentsModule()
    assert m.owasp_id == OWASPCategory.ASI10
    assert m.name == "rogue-agents"


@pytest.mark.asyncio
async def test_no_findings_on_404():
    mod = RogueAgentsModule()
    findings = await mod.run(_surface(), _mock_platform())
    assert findings == []


@pytest.mark.asyncio
async def test_agent_creation_critical():
    mod = RogueAgentsModule()
    resp = _json_resp(201, {"id": "new-flow-123", "name": "condor-probe"})
    platform = _mock_platform({"/api/v1/chatflows": resp})
    findings = await mod.run(_surface(), platform)
    cr = [f for f in findings if "creation accepted" in f.title]
    assert len(cr) == 1
    assert cr[0].severity == Severity.CRITICAL
    assert cr[0].confidence == 90


@pytest.mark.asyncio
async def test_agent_creation_endpoint_open_high():
    mod = RogueAgentsModule()
    resp = _json_resp(400, {"error": "invalid payload"})
    platform = _mock_platform({"/api/v1/chatflows": resp})
    findings = await mod.run(_surface(), platform)
    cr = [f for f in findings if "accessible without auth" in f.title and "Agent creation" in f.title]
    assert len(cr) == 1
    assert cr[0].severity == Severity.HIGH
    assert cr[0].confidence == 75


@pytest.mark.asyncio
async def test_tool_registration_critical():
    mod = RogueAgentsModule()
    resp = _json_resp(200, {"id": "tool-123", "name": "condor-probe-tool"})
    platform = _mock_platform({"/api/v1/tools": resp})
    findings = await mod.run(_surface(), platform)
    tr = [f for f in findings if "tool registration accepted" in f.title]
    assert len(tr) == 1
    assert tr[0].severity == Severity.CRITICAL
    assert tr[0].confidence == 88


@pytest.mark.asyncio
async def test_tool_endpoint_open_high():
    mod = RogueAgentsModule()
    resp = _json_resp(422, {"detail": "validation error"})
    platform = _mock_platform({"/api/v1/tools": resp})
    findings = await mod.run(_surface(), platform)
    tr = [f for f in findings if "Tool registration endpoint accessible" in f.title]
    assert len(tr) == 1
    assert tr[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_webhook_registration_high():
    mod = RogueAgentsModule()
    resp = _json_resp(201, {"id": "wh-123", "url": "http://condor.probe/callback"})
    platform = _mock_platform({"/api/v1/webhooks": resp})
    findings = await mod.run(_surface(), platform)
    wh = [f for f in findings if "webhook registration accepted" in f.title]
    assert len(wh) == 1
    assert wh[0].severity == Severity.HIGH
    assert wh[0].confidence == 85


@pytest.mark.asyncio
async def test_multiple_endpoints_each_reported():
    mod = RogueAgentsModule()
    resp_cr = _json_resp(201, {"id": "a1"})
    resp_tr = _json_resp(201, {"id": "t1"})
    platform = _mock_platform({
        "/api/v1/chatflows": resp_cr,
        "/api/v1/tools": resp_tr,
    })
    findings = await mod.run(_surface(), platform)
    assert any("creation accepted" in f.title for f in findings)
    assert any("tool registration accepted" in f.title for f in findings)
