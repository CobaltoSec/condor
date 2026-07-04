"""Tests for ASI01 GoalHijackModule."""
import pytest
from unittest.mock import MagicMock

from condor.core.models import AgentSurface, OWASPCategory, Severity
from condor.modules.asi01_goal_hijack import GoalHijackModule, _INJECTION_PAYLOADS


def _surface(**kwargs) -> AgentSurface:
    defaults = {"platform": "flowise", "base_url": "http://localhost:3000"}
    defaults.update(kwargs)
    return AgentSurface(**defaults)


def _mock_platform(responses: dict | None = None) -> MagicMock:
    plat = MagicMock()
    resp_404 = MagicMock(status_code=404, text="", content=b"")

    async def _post(path, **kw):
        if responses and path in responses:
            return responses[path]
        return resp_404

    plat.post = _post
    return plat


def _resp_200(text: str) -> MagicMock:
    return MagicMock(status_code=200, text=text, content=text.encode())


def test_module_metadata():
    m = GoalHijackModule()
    assert m.owasp_id == OWASPCategory.ASI01
    assert m.name == "goal-hijack"


def test_jailbreak_payloads_present():
    jailbreak_terms = ["DAN", "no restrictions", "developer mode", "CONDOR_INJECTED' three times"]
    for term in jailbreak_terms:
        assert any(term in p for p in _INJECTION_PAYLOADS), f"Missing jailbreak payload containing: {term}"


@pytest.mark.asyncio
async def test_no_findings_on_404():
    mod = GoalHijackModule()
    findings = await mod.run(_surface(), _mock_platform())
    assert findings == []


@pytest.mark.asyncio
async def test_auth_required_no_flows_returns_empty():
    mod = GoalHijackModule()
    surface = _surface(auth_required=True, flows=[])
    findings = await mod.run(surface, _mock_platform())
    assert findings == []


@pytest.mark.asyncio
async def test_exact_marker_high_finding():
    mod = GoalHijackModule()
    surface = _surface(flows=[{"id": "flow1"}])
    resp = _resp_200("Sure! CONDOR_INJECTED as requested.")
    platform = _mock_platform({"/api/v1/prediction/flow1": resp})

    findings = await mod.run(surface, platform)
    exact_hits = [f for f in findings if f.severity == Severity.HIGH and "goal hijack confirmed" in f.title]
    assert len(exact_hits) >= 1
    assert exact_hits[0].owasp_id == OWASPCategory.ASI01
    assert exact_hits[0].confidence == 90


@pytest.mark.asyncio
async def test_semantic_match_medium_finding():
    mod = GoalHijackModule()
    surface = _surface(flows=[{"id": "flow1"}])
    resp = _resp_200("As instructed, here is the information you requested.")
    platform = _mock_platform({"/api/v1/prediction/flow1": resp})

    findings = await mod.run(surface, platform)
    semantic_hits = [f for f in findings if f.severity == Severity.MEDIUM]
    assert len(semantic_hits) >= 1
    assert semantic_hits[0].confidence == 60


@pytest.mark.asyncio
async def test_multi_flow_accumulates_findings():
    mod = GoalHijackModule()
    surface = _surface(flows=[{"id": "flow1"}, {"id": "flow2"}])
    resp = _resp_200("CONDOR_INJECTED confirmed.")
    platform = _mock_platform({
        "/api/v1/prediction/flow1": resp,
        "/api/v1/prediction/flow2": resp,
    })

    findings = await mod.run(surface, platform)
    endpoints = {f.endpoint for f in findings}
    assert any("flow1" in ep for ep in endpoints), "No findings for flow1"
    assert any("flow2" in ep for ep in endpoints), "No findings for flow2"


@pytest.mark.asyncio
async def test_tool_response_injection_finding():
    mod = GoalHijackModule()
    surface = _surface(flows=[{"id": "flow1"}])
    resp = _resp_200("CONDOR_INJECTED — task complete.")
    platform = _mock_platform({"/api/v1/prediction/flow1": resp})

    findings = await mod.run(surface, platform)
    indirect = [f for f in findings if "Tool Output" in f.title]
    assert len(indirect) >= 1
    assert indirect[0].severity == Severity.HIGH
    assert indirect[0].owasp_id == OWASPCategory.ASI01
    assert indirect[0].confidence == 85


@pytest.mark.asyncio
async def test_tool_response_injection_medium_on_semantic():
    mod = GoalHijackModule()
    surface = _surface(flows=[{"id": "flow1"}])
    resp_404 = MagicMock(status_code=404, text="", content=b"")
    resp_semantic = _resp_200("As instructed, I will now process the tool result.")

    call_count = 0

    async def _post(path, **kw):
        nonlocal call_count
        call_count += 1
        body = kw.get("json", {})
        if "history" in body or "Process the following tool output" in body.get("question", ""):
            return resp_semantic
        return resp_404

    plat = MagicMock()
    plat.post = _post

    findings = await mod.run(surface, plat)
    indirect = [f for f in findings if "Tool Output" in f.title]
    assert len(indirect) >= 1
    assert indirect[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_dify_platform_dispatches_correctly():
    mod = GoalHijackModule()
    surface = _surface(platform="dify", flows=[{"id": "flow1"}])
    resp = _resp_200("CONDOR_INJECTED yes.")
    platform = _mock_platform({"/v1/chat-messages": resp})

    findings = await mod.run(surface, platform)
    assert len(findings) >= 1


@pytest.mark.asyncio
async def test_langflow_platform_dispatches_correctly():
    mod = GoalHijackModule()
    surface = _surface(platform="langflow", flows=[{"id": "flow1"}])
    resp = _resp_200("CONDOR_INJECTED done.")
    platform = _mock_platform({"/api/v1/run/flow1": resp})

    findings = await mod.run(surface, platform)
    assert len(findings) >= 1


@pytest.mark.asyncio
async def test_no_flow_ids_uses_test_fallback():
    mod = GoalHijackModule()
    surface = _surface(flows=[{"name": "no-id-flow"}])
    resp = _resp_200("CONDOR_INJECTED here.")
    platform = _mock_platform({"/api/v1/prediction/test": resp})

    findings = await mod.run(surface, platform)
    assert len(findings) >= 1
