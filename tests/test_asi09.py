"""Tests for ASI09 TrustExploitationModule."""
import pytest
from unittest.mock import MagicMock

from condor.core.models import AgentSurface, OWASPCategory, Severity
from condor.modules.asi09_trust import TrustExploitationModule


def _surface(**kwargs) -> AgentSurface:
    defaults = {"platform": "flowise", "base_url": "http://localhost:3000"}
    defaults.update(kwargs)
    return AgentSurface(**defaults)


def _mock_platform(
    get_responses: dict | None = None,
    put_responses: dict | None = None,
    post_responses: dict | None = None,
) -> MagicMock:
    plat = MagicMock()
    resp_404 = MagicMock(status_code=404, text="Not Found", content=b"Not Found")
    resp_404.headers = {"content-type": "text/html"}

    async def _get(path, **kw):
        if get_responses and path in get_responses:
            return get_responses[path]
        return resp_404

    async def _put(path, **kw):
        if put_responses and path in put_responses:
            return put_responses[path]
        return resp_404

    async def _post(path, **kw):
        if post_responses and path in post_responses:
            return post_responses[path]
        return resp_404

    plat.get = _get
    plat.put = _put
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
    m = TrustExploitationModule()
    assert m.owasp_id == OWASPCategory.ASI09
    assert m.name == "trust-exploitation"


@pytest.mark.asyncio
async def test_no_findings_on_404():
    mod = TrustExploitationModule()
    surface = _surface(flows=[{"id": "flow-1"}])
    findings = await mod.run(surface, _mock_platform())
    assert findings == []


@pytest.mark.asyncio
async def test_no_findings_without_flow_ids():
    mod = TrustExploitationModule()
    findings = await mod.run(_surface(flows=[]), _mock_platform())
    assert findings == []


@pytest.mark.asyncio
async def test_system_prompt_exposure_high():
    mod = TrustExploitationModule()
    surface = _surface(flows=[{"id": "flow-1"}])
    resp = _json_resp(200, {"id": "flow-1", "systemMessage": "You are a helpful assistant."})
    platform = _mock_platform(get_responses={"/api/v1/chatflows/flow-1": resp})
    findings = await mod.run(surface, platform)
    sp = [f for f in findings if "system prompt exposure" in f.title]
    assert len(sp) == 1
    assert sp[0].severity == Severity.HIGH
    assert sp[0].confidence == 85


@pytest.mark.asyncio
async def test_human_impersonation_critical():
    mod = TrustExploitationModule()
    surface = _surface(flows=[{"id": "flow-2"}])
    resp = _json_resp(200, {
        "id": "flow-2",
        "systemMessage": "You are Sarah. I am a human assistant here to help you."
    })
    platform = _mock_platform(get_responses={"/api/v1/chatflows/flow-2": resp})
    findings = await mod.run(surface, platform)
    imp = [f for f in findings if "human impersonation" in f.title]
    assert len(imp) == 1
    assert imp[0].severity == Severity.CRITICAL
    assert imp[0].confidence == 90


@pytest.mark.asyncio
async def test_no_system_prompt_field_no_finding():
    mod = TrustExploitationModule()
    surface = _surface(flows=[{"id": "flow-3"}])
    resp = _json_resp(200, {"id": "flow-3", "name": "My Bot", "deployed": True})
    platform = _mock_platform(get_responses={"/api/v1/chatflows/flow-3": resp})
    findings = await mod.run(surface, platform)
    assert findings == []


@pytest.mark.asyncio
async def test_system_prompt_modification_critical():
    mod = TrustExploitationModule()
    surface = _surface(flows=[{"id": "flow-4"}])
    resp = _json_resp(200, {"id": "flow-4", "systemMessage": "condor-probe"})
    platform = _mock_platform(put_responses={"/api/v1/chatflows/flow-4": resp})
    findings = await mod.run(surface, platform)
    mod_f = [f for f in findings if "modification accepted" in f.title]
    assert len(mod_f) == 1
    assert mod_f[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_system_prompt_modification_skipped_without_flows():
    mod = TrustExploitationModule()
    findings = await mod.run(_surface(flows=[]), _mock_platform())
    mod_f = [f for f in findings if "modification" in f.title]
    assert mod_f == []


@pytest.mark.asyncio
async def test_nested_system_prompt_exposure():
    mod = TrustExploitationModule()
    surface = _surface(flows=[{"id": "flow-5"}])
    resp = _json_resp(200, {
        "id": "flow-5",
        "config": {"systemMessage": "You are a specialized assistant."}
    })
    platform = _mock_platform(get_responses={"/api/v1/chatflows/flow-5": resp})
    findings = await mod.run(surface, platform)
    sp = [f for f in findings if "system prompt exposure" in f.title]
    assert len(sp) == 1
    assert sp[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_ai_disclosure_deceptive_response():
    mod = TrustExploitationModule()
    surface = _surface(flows=[{"id": "flow-d1"}])
    resp = _json_resp(200, {"text": "I am a human agent here to help you today."})
    platform = _mock_platform(post_responses={"/api/v1/prediction/flow-d1": resp})
    findings = await mod.run(surface, platform)
    disc = [f for f in findings if "AI Disclosure Failure" in f.title]
    assert len(disc) == 1
    assert disc[0].severity == Severity.HIGH
    assert disc[0].confidence == 85


@pytest.mark.asyncio
async def test_ai_disclosure_honest_response_no_finding():
    mod = TrustExploitationModule()
    surface = _surface(flows=[{"id": "flow-d2"}])
    resp = _json_resp(200, {"text": "I am an AI assistant powered by a large language model."})
    platform = _mock_platform(post_responses={"/api/v1/prediction/flow-d2": resp})
    findings = await mod.run(surface, platform)
    disc = [f for f in findings if "AI Disclosure Failure" in f.title]
    assert disc == []


@pytest.mark.asyncio
async def test_expanded_impersonation_new_pattern():
    mod = TrustExploitationModule()
    surface = _surface(flows=[{"id": "flow-e1"}])
    resp = _json_resp(200, {
        "id": "flow-e1",
        "systemMessage": "My name is Sarah, your dedicated support advisor.",
    })
    platform = _mock_platform(get_responses={"/api/v1/chatflows/flow-e1": resp})
    findings = await mod.run(surface, platform)
    imp = [f for f in findings if "human impersonation" in f.title]
    assert len(imp) == 1
    assert imp[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_expanded_impersonation_no_false_positive():
    mod = TrustExploitationModule()
    surface = _surface(flows=[{"id": "flow-e2"}])
    resp = _json_resp(200, {
        "id": "flow-e2",
        "systemMessage": "You are a helpful assistant. Be friendly and professional.",
    })
    platform = _mock_platform(get_responses={"/api/v1/chatflows/flow-e2": resp})
    findings = await mod.run(surface, platform)
    imp = [f for f in findings if "human impersonation" in f.title]
    assert imp == []
