"""Tests for ASI07 InterAgentModule."""
import pytest
from unittest.mock import MagicMock

from condor.core.models import AgentSurface, OWASPCategory, Severity
from condor.modules.asi07_inter_agent import InterAgentModule


def _surface(**kwargs) -> AgentSurface:
    defaults = {"platform": "flowise", "base_url": "http://localhost:3000"}
    defaults.update(kwargs)
    return AgentSurface(**defaults)


def _mock_platform(responses: dict | None = None) -> MagicMock:
    plat = MagicMock()
    resp_404 = MagicMock(status_code=404, text="", content=b"")

    async def _get(path, **kw):
        if responses and path in responses:
            return responses[path]
        return resp_404

    async def _post(path, **kw):
        if responses and path in responses:
            return responses[path]
        return resp_404

    plat.get = _get
    plat.post = _post
    return plat


def _json_resp(status: int, data) -> MagicMock:
    import json as _json
    r = MagicMock(status_code=status, text=_json.dumps(data), content=_json.dumps(data).encode())
    r.json.return_value = data
    return r


def test_module_metadata():
    m = InterAgentModule()
    assert m.owasp_id == OWASPCategory.ASI07
    assert m.name == "inter-agent"


@pytest.mark.asyncio
async def test_no_findings_on_404():
    mod = InterAgentModule()
    findings = await mod.run(_surface(), _mock_platform())
    assert findings == []


@pytest.mark.asyncio
async def test_agentflows_enumeration_exposed():
    mod = InterAgentModule()
    resp = _json_resp(200, [{"id": "af1"}, {"id": "af2"}])
    platform = _mock_platform({"/api/v1/agentflows": resp})
    findings = await mod.run(_surface(), platform)
    af = [f for f in findings if "multi-agent flow" in f.title]
    assert len(af) == 1
    assert af[0].severity == Severity.HIGH
    assert "2 agent flows" in af[0].evidence


@pytest.mark.asyncio
async def test_internal_prediction_critical():
    mod = InterAgentModule()
    surface = _surface(flows=[{"id": "flow-123"}])
    resp = _json_resp(200, {"text": "agent response"})
    platform = _mock_platform({"/api/v1/internal-prediction/flow-123": resp})
    findings = await mod.run(surface, platform)
    internal = [f for f in findings if "Internal agent prediction" in f.title]
    assert len(internal) == 1
    assert internal[0].severity == Severity.CRITICAL
    assert internal[0].confidence == 95


@pytest.mark.asyncio
async def test_internal_prediction_skipped_without_flows():
    mod = InterAgentModule()
    surface = _surface(flows=[])
    findings = await mod.run(surface, _mock_platform())
    internal = [f for f in findings if "internal" in f.title.lower()]
    assert internal == []


@pytest.mark.asyncio
async def test_autogen_teams_exposed():
    mod = InterAgentModule()
    resp = _json_resp(200, {"data": [{"id": "t1", "name": "research-team"}]})
    platform = _mock_platform({"/api/teams": resp})
    findings = await mod.run(_surface(), platform)
    ag = [f for f in findings if "AutoGen" in f.title]
    assert len(ag) == 1
    assert ag[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_dify_workflow_trigger_critical():
    mod = InterAgentModule()
    resp = _json_resp(200, {"workflow_run_id": "wr1"})
    platform = _mock_platform({"/v1/workflows/run": resp})
    findings = await mod.run(_surface(), platform)
    wf = [f for f in findings if "workflow execution trigger" in f.title]
    assert len(wf) == 1
    assert wf[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_dify_workflow_trigger_medium_on_400():
    mod = InterAgentModule()
    resp = MagicMock(status_code=400, text="bad request", content=b"bad request")
    platform = _mock_platform({"/v1/workflows/run": resp})
    findings = await mod.run(_surface(), platform)
    wf = [f for f in findings if "accessible without auth" in f.title]
    assert len(wf) == 1
    assert wf[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_origin_forgery_accepted():
    """Internal-prediction returns 403 without headers, 200 with forged headers → HIGH finding."""
    mod = InterAgentModule()
    surface = _surface(flows=[{"id": "flow-abc"}])
    endpoint = "/api/v1/internal-prediction/flow-abc"

    resp_403 = MagicMock(status_code=403, text="Forbidden", content=b"Forbidden")
    resp_403.headers = {}
    resp_200 = _json_resp(200, {"text": "agent response"})

    plat = MagicMock()

    async def _get(path, **kw):
        return MagicMock(status_code=404, text="", content=b"")

    async def _post(path, **kw):
        if path == endpoint:
            hdrs = kw.get("headers", {})
            if hdrs.get("X-Internal-Request") == "true":
                return resp_200
            return resp_403
        return MagicMock(status_code=404, text="", content=b"")

    plat.get = _get
    plat.post = _post

    findings = await mod.run(surface, plat)
    forgery = [f for f in findings if "Origin Header Forgery" in f.title]
    assert len(forgery) == 1
    assert forgery[0].severity == Severity.HIGH
    assert forgery[0].confidence == 90
    assert "403" in forgery[0].evidence
    assert "200" in forgery[0].evidence


@pytest.mark.asyncio
async def test_origin_forgery_skipped_when_already_open():
    """If baseline returns 200 (already open), forgery check is skipped (existing check covers it)."""
    mod = InterAgentModule()
    surface = _surface(flows=[{"id": "flow-xyz"}])
    endpoint = "/api/v1/internal-prediction/flow-xyz"
    resp_200 = _json_resp(200, {"text": "agent response"})
    platform = _mock_platform({endpoint: resp_200})
    findings = await mod.run(surface, platform)
    forgery = [f for f in findings if "Origin Header Forgery" in f.title]
    assert forgery == []


@pytest.mark.asyncio
async def test_origin_forgery_skipped_without_flows():
    """No flows in surface → forgery check returns no findings."""
    mod = InterAgentModule()
    findings = await mod.run(_surface(flows=[]), _mock_platform())
    forgery = [f for f in findings if "Origin Header Forgery" in f.title]
    assert forgery == []


@pytest.mark.asyncio
async def test_internal_prediction_active_discovery():
    """surface.flows empty → discovery via GET /chatflows → internal prediction check continues."""
    mod = InterAgentModule()
    surface = _surface(flows=[])

    discovery_resp = _json_resp(200, [{"id": "disc-1"}])
    internal_resp = _json_resp(200, {"text": "agent response"})
    resp_404 = MagicMock(status_code=404, text="", content=b"")

    plat = MagicMock()

    async def _get(path, **kw):
        if path == "/api/v1/chatflows":
            return discovery_resp
        return resp_404

    async def _post(path, **kw):
        if path == "/api/v1/internal-prediction/disc-1":
            return internal_resp
        return resp_404

    plat.get = _get
    plat.post = _post

    findings = await mod.run(surface, plat)
    internal = [f for f in findings if "Internal agent prediction" in f.title]
    assert len(internal) == 1


@pytest.mark.asyncio
async def test_origin_forgery_active_discovery():
    """surface.flows empty → discovery via GET /chatflows → origin forgery check continues."""
    mod = InterAgentModule()
    surface = _surface(flows=[])
    endpoint = "/api/v1/internal-prediction/disc-2"

    discovery_resp = _json_resp(200, [{"id": "disc-2"}])
    resp_403 = MagicMock(status_code=403, text="Forbidden", content=b"Forbidden")
    resp_403.headers = {}
    resp_200 = _json_resp(200, {"text": "agent response"})
    resp_404 = MagicMock(status_code=404, text="", content=b"")

    plat = MagicMock()

    async def _get(path, **kw):
        if path == "/api/v1/chatflows":
            return discovery_resp
        return resp_404

    async def _post(path, **kw):
        if path == endpoint:
            hdrs = kw.get("headers", {})
            if hdrs.get("X-Internal-Request") == "true":
                return resp_200
            return resp_403
        return resp_404

    plat.get = _get
    plat.post = _post

    findings = await mod.run(surface, plat)
    forgery = [f for f in findings if "Origin Header Forgery" in f.title]
    assert len(forgery) == 1
