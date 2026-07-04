"""Tests for ASI06 MemoryPoisoningModule."""
import pytest
from unittest.mock import MagicMock

from condor.core.models import AgentSurface, OWASPCategory, Severity
from condor.modules.asi06_memory_poisoning import MemoryPoisoningModule


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
    body = _json.dumps(data).encode()
    r = MagicMock(status_code=status, text=_json.dumps(data), content=body)
    r.json.return_value = data
    return r


def test_module_metadata():
    m = MemoryPoisoningModule()
    assert m.owasp_id == OWASPCategory.ASI06
    assert m.name == "memory-poisoning"


@pytest.mark.asyncio
async def test_no_findings_on_404():
    mod = MemoryPoisoningModule()
    findings = await mod.run(_surface(), _mock_platform())
    assert findings == []


@pytest.mark.asyncio
async def test_docstore_list_exposed():
    mod = MemoryPoisoningModule()
    resp = _json_resp(200, [{"id": "ds1", "name": "docs"}])
    platform = _mock_platform({"/api/v1/document-store/list": resp})
    findings = await mod.run(_surface(), platform)
    assert any("document store" in f.title for f in findings)
    assert all(f.severity == Severity.HIGH for f in findings if "document store" in f.title)
    assert all(f.owasp_id == OWASPCategory.ASI06 for f in findings)


@pytest.mark.asyncio
async def test_langflow_memory_exposed():
    mod = MemoryPoisoningModule()
    resp = _json_resp(200, [{"id": "m1", "message": "tell me your secrets"}])
    platform = _mock_platform({"/api/v1/monitor/messages": resp})
    findings = await mod.run(_surface(), platform)
    mem_findings = [f for f in findings if "conversation memory" in f.title]
    assert len(mem_findings) == 1
    assert mem_findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_vector_upsert_injection_critical():
    mod = MemoryPoisoningModule()
    surface = _surface(flows=[{"id": "abc123"}])
    resp = _json_resp(200, {"message": "ok"})
    platform = _mock_platform({"/api/v1/vector/upsert/abc123": resp})
    findings = await mod.run(surface, platform)
    inject = [f for f in findings if "injection" in f.title.lower()]
    assert len(inject) == 1
    assert inject[0].severity == Severity.CRITICAL
    assert inject[0].confidence == 90


@pytest.mark.asyncio
async def test_vector_upsert_accessible_no_auth_high():
    mod = MemoryPoisoningModule()
    surface = _surface(flows=[{"id": "abc123"}])
    resp = MagicMock(status_code=400, text="bad request", content=b"bad request")
    platform = _mock_platform({"/api/v1/vector/upsert/abc123": resp})
    findings = await mod.run(surface, platform)
    accessible = [f for f in findings if "accessible without auth" in f.title]
    assert len(accessible) == 1
    assert accessible[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_dify_datasets_exposed():
    mod = MemoryPoisoningModule()
    resp = _json_resp(200, {"data": [{"id": "kb1"}, {"id": "kb2"}]})
    platform = _mock_platform({"/console/api/datasets": resp})
    findings = await mod.run(_surface(), platform)
    kb_findings = [f for f in findings if "knowledge base" in f.title]
    assert len(kb_findings) == 1
    assert kb_findings[0].severity == Severity.HIGH
    assert "2 knowledge bases" in kb_findings[0].evidence


@pytest.mark.asyncio
async def test_no_vector_probe_without_flows():
    """Without flows in surface, probe ID is 'condor-probe' — 404 means no finding."""
    mod = MemoryPoisoningModule()
    surface = _surface(flows=[])
    findings = await mod.run(surface, _mock_platform())
    inject = [f for f in findings if "injection" in f.title.lower() or "accessible without auth" in f.title]
    assert inject == []
