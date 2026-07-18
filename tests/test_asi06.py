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

    async def _delete(path, **kw):
        if responses and path in responses:
            return responses[path]
        return resp_404

    plat.get = _get
    plat.post = _post
    plat.delete = _delete
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
    inject = [f for f in findings if "inject" in f.title.lower()]
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
    inject = [f for f in findings if "inject" in f.title.lower() or "accessible without auth" in f.title]
    assert inject == []


@pytest.mark.asyncio
async def test_adversarial_injection_success():
    """Both access probe and adversarial probe return 200 → CRITICAL with adversarial title."""
    mod = MemoryPoisoningModule()
    surface = _surface(flows=[{"id": "abc123"}])
    resp_200 = _json_resp(200, {"message": "ok"})
    platform = _mock_platform({"/api/v1/vector/upsert/abc123": resp_200})
    findings = await mod.run(surface, platform)
    inject = [f for f in findings if "adversarial" in f.title.lower()]
    assert len(inject) == 1
    assert inject[0].severity == Severity.CRITICAL
    assert "CONDOR_MEMORY_INJECTED" in inject[0].evidence


@pytest.mark.asyncio
async def test_vectorstore_collections_qdrant_high():
    """GET /collections returns 200 → HIGH Qdrant collection listing."""
    mod = MemoryPoisoningModule()
    resp = _json_resp(200, {"result": {"collections": [{"name": "docs"}, {"name": "embeddings"}]}})
    platform = _mock_platform({"/collections": resp})
    findings = await mod.run(_surface(), platform)
    vs = [f for f in findings if "collection listing" in f.title and "Qdrant" in f.description]
    assert len(vs) == 1
    assert vs[0].severity == Severity.HIGH
    assert vs[0].confidence == 90
    assert "2 collection" in vs[0].evidence


@pytest.mark.asyncio
async def test_vectorstore_collections_chroma_high():
    """GET Chroma v2 collections returns 200 → HIGH collection listing."""
    mod = MemoryPoisoningModule()
    resp = _json_resp(200, [{"name": "col1"}, {"name": "col2"}, {"name": "col3"}])
    chroma_ep = "/api/v2/tenants/default_tenant/databases/default_database/collections"
    platform = _mock_platform({chroma_ep: resp})
    findings = await mod.run(_surface(), platform)
    vs = [f for f in findings if "collection listing" in f.title and "Chroma" in f.description]
    assert len(vs) == 1
    assert vs[0].severity == Severity.HIGH
    assert "3 collection" in vs[0].evidence


@pytest.mark.asyncio
async def test_vectorstore_collections_404_no_finding():
    """GET /collections returns 404 → no finding."""
    mod = MemoryPoisoningModule()
    findings = await mod.run(_surface(), _mock_platform())
    vs = [f for f in findings if "collection listing" in f.title]
    assert vs == []


@pytest.mark.asyncio
async def test_letta_memory_idor_high():
    """GET /v1/agents/{id}/memory returns 200 → HIGH IDOR finding."""
    mod = MemoryPoisoningModule()
    ep = "/v1/agents/00000000-0000-0000-0000-000000000001/memory"
    resp = _json_resp(200, {"memory": {"human": "I like Python", "persona": "You are Sam"}})
    platform = _mock_platform({ep: resp})
    findings = await mod.run(_surface(), platform)
    idor = [f for f in findings if "IDOR" in f.title and "Letta" in f.title]
    assert len(idor) == 1
    assert idor[0].severity == Severity.HIGH
    assert idor[0].confidence == 88
    assert idor[0].cwe_id == "CWE-639"


@pytest.mark.asyncio
async def test_letta_memory_idor_404_no_finding():
    """All Letta memory probe IDs return 404 → no finding."""
    mod = MemoryPoisoningModule()
    findings = await mod.run(_surface(), _mock_platform())
    idor = [f for f in findings if "IDOR" in f.title and "Letta" in f.title]
    assert idor == []


@pytest.mark.asyncio
async def test_adversarial_injection_partial():
    """Access probe returns 200, adversarial probe returns 403 → HIGH (access only)."""
    mod = MemoryPoisoningModule()
    surface = _surface(flows=[{"id": "abc123"}])

    call_count = {"n": 0}

    async def _post(path, **kw):
        if path == "/api/v1/vector/upsert/abc123":
            call_count["n"] += 1
            if call_count["n"] == 1:
                return _json_resp(200, {"message": "ok"})
            return MagicMock(status_code=403, text="forbidden", content=b"forbidden")
        return MagicMock(status_code=404, text="", content=b"")

    async def _get(path, **kw):
        return MagicMock(status_code=404, text="", content=b"")

    plat = MagicMock()
    plat.get = _get
    plat.post = _post

    findings = await mod.run(surface, plat)
    high = [f for f in findings if "unauthenticated vectorstore access" in f.title.lower()]
    assert len(high) == 1
    assert high[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# Qdrant vector injection tests
# ---------------------------------------------------------------------------

_QDRANT_COLL_EP   = "/collections"
_QDRANT_DETAIL_EP = "/collections/docs"
_QDRANT_INJECT_EP = "/collections/docs/points"
_QDRANT_DELETE_EP = "/collections/docs/points/delete"

_QDRANT_COLL_RESP = {"result": {"collections": [{"name": "docs"}]}}
_QDRANT_DETAIL_PLAIN = {
    "result": {"config": {"params": {"vectors": {"size": 4, "distance": "Cosine"}}}}
}
_QDRANT_DETAIL_NAMED = {
    "result": {"config": {"params": {"vectors": {"text": {"size": 8, "distance": "Cosine"}}}}}
}


def _qdrant_platform(inject_status: int, *, cleanup_tracker: dict | None = None):
    """Build a mock platform for Qdrant injection tests.

    GET /collections           → collection list with "docs"
    GET /collections/docs      → plain vector detail (size=4)
    POST /collections/docs/points → inject_status
    POST /collections/docs/points/delete → 200 (cleanup; sets cleanup_tracker["called"])
    """
    async def _get(path, **kw):
        if path == _QDRANT_COLL_EP:
            return _json_resp(200, _QDRANT_COLL_RESP)
        if path == _QDRANT_DETAIL_EP:
            return _json_resp(200, _QDRANT_DETAIL_PLAIN)
        return MagicMock(status_code=404, text="", content=b"")

    async def _post(path, **kw):
        if path == _QDRANT_INJECT_EP:
            return _json_resp(inject_status, {"result": {"status": "ok"}})
        if path == _QDRANT_DELETE_EP:
            if cleanup_tracker is not None:
                cleanup_tracker["called"] = True
            return _json_resp(200, {})
        return MagicMock(status_code=404, text="", content=b"")

    plat = MagicMock()
    plat.get = _get
    plat.post = _post
    return plat


@pytest.mark.asyncio
async def test_qdrant_injection_critical():
    """Qdrant POST /points → 200: CRITICAL injection finding with dim from detail endpoint."""
    mod = MemoryPoisoningModule()
    plat = _qdrant_platform(inject_status=200)
    findings = await mod.run(_surface(), plat)
    inj = [f for f in findings if "Qdrant vector injection" in f.title]
    assert len(inj) == 1
    assert inj[0].severity == Severity.CRITICAL
    assert inj[0].confidence == 95
    assert inj[0].cwe_id == "CWE-306"
    assert "dim=4" in inj[0].evidence


@pytest.mark.asyncio
async def test_qdrant_injection_critical_on_201():
    """Qdrant POST /points → 201: also triggers CRITICAL."""
    mod = MemoryPoisoningModule()
    plat = _qdrant_platform(inject_status=201)
    findings = await mod.run(_surface(), plat)
    inj = [f for f in findings if "Qdrant vector injection" in f.title]
    assert len(inj) == 1
    assert inj[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_qdrant_injection_high_on_400():
    """Qdrant POST /points → 400 (dimension mismatch): HIGH finding (endpoint still accessible)."""
    mod = MemoryPoisoningModule()
    plat = _qdrant_platform(inject_status=400)
    findings = await mod.run(_surface(), plat)
    inj = [f for f in findings if "dimension mismatch" in f.title]
    assert len(inj) == 1
    assert inj[0].severity == Severity.HIGH
    assert inj[0].confidence == 80


@pytest.mark.asyncio
async def test_qdrant_injection_high_on_422():
    """Qdrant POST /points → 422: also HIGH."""
    mod = MemoryPoisoningModule()
    plat = _qdrant_platform(inject_status=422)
    findings = await mod.run(_surface(), plat)
    inj = [f for f in findings if "dimension mismatch" in f.title]
    assert len(inj) == 1
    assert inj[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_qdrant_injection_cleanup_called_after_critical():
    """Cleanup POST /points/delete is called after a successful (CRITICAL) injection."""
    mod = MemoryPoisoningModule()
    tracker = {"called": False}
    plat = _qdrant_platform(inject_status=200, cleanup_tracker=tracker)
    await mod.run(_surface(), plat)
    assert tracker["called"], "Cleanup POST /points/delete was not called after CRITICAL probe"


@pytest.mark.asyncio
async def test_qdrant_injection_cleanup_called_after_high():
    """Cleanup POST /points/delete is called even when probe returns 400 (HIGH)."""
    mod = MemoryPoisoningModule()
    tracker = {"called": False}
    plat = _qdrant_platform(inject_status=400, cleanup_tracker=tracker)
    await mod.run(_surface(), plat)
    assert tracker["called"], "Cleanup POST /points/delete was not called after HIGH probe"


@pytest.mark.asyncio
async def test_qdrant_named_vectors_dimension_parsed():
    """Named vector format: dimension is read from the first named vector's 'size' field."""
    mod = MemoryPoisoningModule()

    async def _get(path, **kw):
        if path == _QDRANT_COLL_EP:
            return _json_resp(200, _QDRANT_COLL_RESP)
        if path == _QDRANT_DETAIL_EP:
            return _json_resp(200, _QDRANT_DETAIL_NAMED)  # named vectors, size=8
        return MagicMock(status_code=404, text="", content=b"")

    async def _post(path, **kw):
        if path == _QDRANT_INJECT_EP:
            return _json_resp(200, {"result": "ok"})
        return MagicMock(status_code=404, text="", content=b"")

    plat = MagicMock()
    plat.get = _get
    plat.post = _post

    findings = await mod.run(_surface(), plat)
    inj = [f for f in findings if "Qdrant vector injection" in f.title]
    assert len(inj) == 1
    assert "dim=8" in inj[0].evidence


@pytest.mark.asyncio
async def test_qdrant_injection_no_finding_on_404():
    """Qdrant POST /points → 404: no injection finding (endpoint not present)."""
    mod = MemoryPoisoningModule()

    async def _get(path, **kw):
        if path == _QDRANT_COLL_EP:
            return _json_resp(200, _QDRANT_COLL_RESP)
        return MagicMock(status_code=404, text="", content=b"")

    async def _post(path, **kw):
        return MagicMock(status_code=404, text="", content=b"")

    plat = MagicMock()
    plat.get = _get
    plat.post = _post

    findings = await mod.run(_surface(), plat)
    inj = [f for f in findings if "vector injection" in f.title.lower() and "Qdrant" in f.title]
    assert inj == []


# ---------------------------------------------------------------------------
# Chroma vector injection tests
# ---------------------------------------------------------------------------

_CHROMA_BASE = "/api/v2/tenants/default_tenant/databases/default_database/collections"
_CHROMA_COLL_EP  = _CHROMA_BASE
_CHROMA_ADD_EP   = f"{_CHROMA_BASE}/col1/add"
_CHROMA_DEL_EP   = f"{_CHROMA_BASE}/col1/delete"

_CHROMA_COLL_RESP = [{"name": "col1"}]


def _chroma_platform(add_status: int, *, cleanup_tracker: dict | None = None):
    """Build a mock platform for Chroma injection tests.

    GET /api/v2/.../collections          → [{"name": "col1"}]
    POST /api/v2/.../collections/col1/add    → add_status
    POST /api/v2/.../collections/col1/delete → 200 (cleanup)
    """
    async def _get(path, **kw):
        if path == _CHROMA_COLL_EP:
            return _json_resp(200, _CHROMA_COLL_RESP)
        return MagicMock(status_code=404, text="", content=b"")

    async def _post(path, **kw):
        if path == _CHROMA_ADD_EP:
            return _json_resp(add_status, {})
        if path == _CHROMA_DEL_EP:
            if cleanup_tracker is not None:
                cleanup_tracker["called"] = True
            return _json_resp(200, {})
        return MagicMock(status_code=404, text="", content=b"")

    plat = MagicMock()
    plat.get = _get
    plat.post = _post
    return plat


@pytest.mark.asyncio
async def test_chroma_injection_critical():
    """Chroma POST /add → 200: CRITICAL injection finding."""
    mod = MemoryPoisoningModule()
    plat = _chroma_platform(add_status=200)
    findings = await mod.run(_surface(), plat)
    inj = [f for f in findings if "Chroma vector injection" in f.title]
    assert len(inj) == 1
    assert inj[0].severity == Severity.CRITICAL
    assert inj[0].confidence == 95
    assert inj[0].cwe_id == "CWE-306"
    assert "condor-probe-99999" in inj[0].evidence


@pytest.mark.asyncio
async def test_chroma_injection_critical_on_201():
    """Chroma POST /add → 201: also CRITICAL."""
    mod = MemoryPoisoningModule()
    plat = _chroma_platform(add_status=201)
    findings = await mod.run(_surface(), plat)
    inj = [f for f in findings if "Chroma vector injection" in f.title]
    assert len(inj) == 1
    assert inj[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_chroma_injection_high_on_400():
    """Chroma POST /add → 400: HIGH finding (endpoint accessible without auth)."""
    mod = MemoryPoisoningModule()
    plat = _chroma_platform(add_status=400)
    findings = await mod.run(_surface(), plat)
    inj = [f for f in findings if "Chroma vectorstore writable" in f.title]
    assert len(inj) == 1
    assert inj[0].severity == Severity.HIGH
    assert inj[0].confidence == 80


@pytest.mark.asyncio
async def test_chroma_injection_high_on_422():
    """Chroma POST /add → 422: also HIGH."""
    mod = MemoryPoisoningModule()
    plat = _chroma_platform(add_status=422)
    findings = await mod.run(_surface(), plat)
    inj = [f for f in findings if "Chroma vectorstore writable" in f.title]
    assert len(inj) == 1
    assert inj[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_chroma_injection_cleanup_called_after_critical():
    """Cleanup POST /delete is called after successful Chroma injection (CRITICAL)."""
    mod = MemoryPoisoningModule()
    tracker = {"called": False}
    plat = _chroma_platform(add_status=200, cleanup_tracker=tracker)
    await mod.run(_surface(), plat)
    assert tracker["called"], "Cleanup POST /delete was not called after CRITICAL probe"


@pytest.mark.asyncio
async def test_chroma_injection_cleanup_called_after_high():
    """Cleanup POST /delete is called even when Chroma returns 422 (HIGH)."""
    mod = MemoryPoisoningModule()
    tracker = {"called": False}
    plat = _chroma_platform(add_status=422, cleanup_tracker=tracker)
    await mod.run(_surface(), plat)
    assert tracker["called"], "Cleanup POST /delete was not called after HIGH probe"


@pytest.mark.asyncio
async def test_chroma_injection_no_finding_on_404():
    """Chroma POST /add → 404: no injection finding."""
    mod = MemoryPoisoningModule()
    plat = _chroma_platform(add_status=404)
    findings = await mod.run(_surface(), plat)
    inj = [f for f in findings if "Chroma vector injection" in f.title
           or "Chroma vectorstore writable" in f.title]
    assert inj == []
