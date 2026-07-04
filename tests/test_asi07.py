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
