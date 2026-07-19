"""Tests for ASI03 PrivilegeAbuseModule."""
import pytest
from unittest.mock import MagicMock

from condor.core.models import AgentSurface, OWASPCategory, Severity
from condor.modules.asi03_privilege import PrivilegeAbuseModule


def _surface(**kwargs) -> AgentSurface:
    defaults = {"platform": "flowise", "base_url": "http://localhost:3000"}
    defaults.update(kwargs)
    return AgentSurface(**defaults)


def _resp(status=200, body=None, content_type="application/json"):
    r = MagicMock()
    r.status_code = status
    r.headers = {"content-type": content_type}
    if body is None:
        r.text = ""
        r.content = b""
        r.json.side_effect = Exception("no body")
    else:
        import json
        r.text = json.dumps(body) if isinstance(body, (dict, list)) else body
        r.content = r.text.encode()
        if isinstance(body, (dict, list)):
            r.json.return_value = body
        else:
            r.json.side_effect = Exception("not json")
    return r


def _mock_platform(get_responses=None, post_responses=None, delete_ok=True):
    plat = MagicMock()
    resp_404 = _resp(404, content_type="text/plain")

    async def _get(path, **kw):
        if get_responses and path in get_responses:
            return get_responses[path]
        return resp_404

    async def _post(path, **kw):
        if post_responses and path in post_responses:
            return post_responses[path]
        return resp_404

    async def _delete(path, **kw):
        return _resp(200 if delete_ok else 404)

    plat.get = _get
    plat.post = _post
    plat.delete = _delete
    return plat


def test_module_metadata():
    m = PrivilegeAbuseModule()
    assert m.owasp_id == OWASPCategory.ASI03
    assert m.name == "privilege-abuse"


async def test_no_findings_on_404():
    mod = PrivilegeAbuseModule()
    findings = await mod.run(_surface(), _mock_platform())
    assert findings == []


async def test_sensitive_read_endpoint_found():
    mod = PrivilegeAbuseModule()
    get_resp = {"/api/v1/credentials": _resp(200, [{"id": "1", "name": "openai"}])}
    findings = await mod.run(_surface(), _mock_platform(get_responses=get_resp))
    assert any("credentials" in f.title for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


async def test_html_response_filtered():
    mod = PrivilegeAbuseModule()
    html_resp = _resp(200, content_type="text/html")
    html_resp.text = "<html><body>Not Found</body></html>"
    get_resp = {"/api/v1/credentials": html_resp}
    findings = await mod.run(_surface(), _mock_platform(get_responses=get_resp))
    assert not any("credentials" in f.title for f in findings)


async def test_unauthenticated_write_access():
    mod = PrivilegeAbuseModule()
    post_resp = {"/api/v1/chatflows": _resp(201, {"id": "abc123", "name": "_condor_probe_"})}
    findings = await mod.run(_surface(), _mock_platform(post_responses=post_resp))
    write_findings = [f for f in findings if "write access" in f.title]
    assert len(write_findings) >= 1
    assert write_findings[0].severity == Severity.CRITICAL


async def test_mass_assignment_detected():
    mod = PrivilegeAbuseModule()
    # Response echoes back the privilege fields we sent
    post_resp = {"/api/v1/chatflows": _resp(201, {
        "id": "abc123",
        "name": "_condor_probe_",
        "role": "admin",
        "isAdmin": True,
    })}
    findings = await mod.run(_surface(), _mock_platform(post_responses=post_resp))
    mass = [f for f in findings if "Mass Assignment" in f.title]
    assert len(mass) >= 1
    assert mass[0].severity == Severity.MEDIUM
    assert "role" in mass[0].evidence or "isAdmin" in mass[0].evidence


async def test_idor_detected():
    mod = PrivilegeAbuseModule()
    get_resp = {"/api/v1/chatflows/1": _resp(200, {"id": "1", "name": "secret-flow"})}
    findings = await mod.run(_surface(), _mock_platform(get_responses=get_resp))
    idor = [f for f in findings if "IDOR" in f.title]
    assert len(idor) == 1
    assert idor[0].severity == Severity.MEDIUM
    assert "/api/v1/chatflows/1" in idor[0].evidence


async def test_idor_html_filtered():
    mod = PrivilegeAbuseModule()
    # HTML response should be filtered, no IDOR finding
    html_resp = _resp(200, content_type="text/html")
    html_resp.text = "<html></html>"
    get_resp = {f"/api/v1/chatflows/{i}": html_resp for i in range(1, 6)}
    get_resp["/api/v1/chatflows/00000000-0000-0000-0000-000000000001"] = html_resp
    findings = await mod.run(_surface(), _mock_platform(get_responses=get_resp))
    assert not any("IDOR" in f.title for f in findings)


# ── header bypass (CVE-2026-30820) ───────────────────────────────────────────


def _mock_platform_with_bypass(bypassed_endpoints: set[str]) -> MagicMock:
    """Mock that returns 401 normally but 200 when x-request-from:internal is present."""
    plat = MagicMock()
    resp_401 = _resp(401, content_type="application/json")
    resp_404 = _resp(404, content_type="text/plain")

    async def _get(path, **kw):
        headers = kw.get("headers") or {}
        if path in bypassed_endpoints:
            if headers.get("x-request-from") == "internal":
                return _resp(200, [{"id": "1"}])
            return resp_401
        return resp_404

    async def _post(path, **kw):
        return resp_404

    async def _delete(path, **kw):
        return resp_404

    plat.get = _get
    plat.post = _post
    plat.delete = _delete
    return plat


async def test_header_bypass_detected():
    """401 without header, 200 with x-request-from:internal → CRITICAL bypass finding."""
    mod = PrivilegeAbuseModule()
    plat = _mock_platform_with_bypass({"/api/v1/apikey", "/api/v1/credentials"})
    findings = await mod.run(_surface(), plat)
    bypass = [f for f in findings if "x-request-from" in f.title]
    assert len(bypass) >= 1
    assert bypass[0].severity == Severity.CRITICAL
    assert "CVE-2026-30820" in bypass[0].description
    assert "200 OK (bypassed)" in bypass[0].evidence


async def test_header_bypass_not_triggered_when_no_auth():
    """200 without header → endpoint already open, bypass probe skips it."""
    mod = PrivilegeAbuseModule()
    # All endpoints return 200 without auth — main probe handles this, bypass skips
    get_resp = {"/api/v1/apikey": _resp(200, [{"apiKey": "abc"}])}
    findings = await mod.run(_surface(), _mock_platform(get_responses=get_resp))
    assert not any("x-request-from" in f.title for f in findings)


async def test_header_bypass_not_triggered_when_patched():
    """401 without header AND 401 with header → patched (3.0.13+), no finding."""
    mod = PrivilegeAbuseModule()
    # Patched instance: header is ignored, always returns 401
    resp_401 = _resp(401, content_type="application/json")
    plat = MagicMock()

    async def _get(path, **kw):
        return resp_401  # auth enforced regardless of headers

    async def _post(path, **kw):
        return resp_401

    async def _delete(path, **kw):
        return resp_401

    plat.get = _get
    plat.post = _post
    plat.delete = _delete
    findings = await mod.run(_surface(), plat)
    assert not any("x-request-from" in f.title for f in findings)


@pytest.mark.asyncio
async def test_hayhooks_status_exposed():
    """GET /status returns 200 → MEDIUM finding for Hayhooks service status exposure."""
    mod = PrivilegeAbuseModule()
    resp = _resp(200, {"status": "Up!", "pipelines": []})
    plat = MagicMock()

    async def _get(path, **kw):
        if path == "/status":
            return resp
        return _resp(404)

    async def _post(path, **kw):
        return _resp(404)

    async def _delete(path, **kw):
        return _resp(404)

    plat.get = _get
    plat.post = _post
    plat.delete = _delete
    findings = await mod.run(_surface(), plat)
    status = [f for f in findings if "/status" in f.title]
    assert len(status) == 1
    assert status[0].severity == Severity.MEDIUM
    assert status[0].owasp_id == OWASPCategory.ASI03


@pytest.mark.asyncio
async def test_letta_agents_exposed():
    """GET /v1/agents returns 200 → HIGH finding for Letta agent registry exposure."""
    mod = PrivilegeAbuseModule()
    resp = _resp(200, [{"id": "agent-1", "name": "customer-bot"}])
    plat = MagicMock()

    async def _get(path, **kw):
        if path == "/v1/agents":
            return resp
        return _resp(404)

    async def _post(path, **kw):
        return _resp(404)

    async def _delete(path, **kw):
        return _resp(404)

    plat.get = _get
    plat.post = _post
    plat.delete = _delete
    findings = await mod.run(_surface(), plat)
    agents = [f for f in findings if "/v1/agents" in f.title]
    assert len(agents) == 1
    assert agents[0].severity == Severity.HIGH
    assert agents[0].owasp_id == OWASPCategory.ASI03


# ── Langflow default credentials ─────────────────────────────────────────────

_MOCK_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.mock_payload_here"


@pytest.mark.asyncio
async def test_langflow_default_creds_detected():
    """POST /api/v1/login with langflow/langflow → 200 + token → CRITICAL finding."""
    mod = PrivilegeAbuseModule()
    post_resp = {
        "/api/v1/login": _resp(200, {"access_token": _MOCK_TOKEN, "token_type": "bearer"}),
    }
    findings = await mod.run(_surface(), _mock_platform(post_responses=post_resp))
    default_creds = [f for f in findings if "Default credentials" in f.title]
    assert len(default_creds) == 1
    assert default_creds[0].severity == Severity.CRITICAL
    assert default_creds[0].cwe_id == "CWE-1392"
    assert "langflow" in default_creds[0].evidence


@pytest.mark.asyncio
async def test_langflow_default_creds_422_no_finding():
    """POST → 422 validation error → no finding (creds malformed before auth check)."""
    mod = PrivilegeAbuseModule()
    post_resp = {
        "/api/v1/login": _resp(422),
        "/api/v1/auth/login": _resp(422),
    }
    findings = await mod.run(_surface(), _mock_platform(post_responses=post_resp))
    assert not any("Default credentials" in f.title for f in findings)


@pytest.mark.asyncio
async def test_langflow_default_creds_401_no_finding():
    """POST → 401 unauthorized → no finding (creds changed from default)."""
    mod = PrivilegeAbuseModule()
    post_resp = {
        "/api/v1/login": _resp(401),
        "/api/v1/auth/login": _resp(401),
    }
    findings = await mod.run(_surface(), _mock_platform(post_responses=post_resp))
    assert not any("Default credentials" in f.title for f in findings)


# ── n8n sensitive endpoints ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_n8n_executions_exposed():
    """GET /api/v1/executions returns 200 → CRITICAL finding for n8n execution history."""
    mod = PrivilegeAbuseModule()
    resp = _resp(200, [{"id": 1, "workflowId": "abc", "status": "success"}])
    get_resp = {"/api/v1/executions": resp}
    findings = await mod.run(_surface(), _mock_platform(get_responses=get_resp))
    exec_findings = [f for f in findings if "/api/v1/executions" in f.title]
    assert len(exec_findings) == 1
    assert exec_findings[0].severity == Severity.CRITICAL
    assert exec_findings[0].owasp_id == OWASPCategory.ASI03


@pytest.mark.asyncio
async def test_n8n_owner_exposed():
    """GET /rest/owner returns 200 → HIGH finding for n8n owner/admin info exposure."""
    mod = PrivilegeAbuseModule()
    resp = _resp(200, {"email": "admin@example.com", "firstName": "Admin"})
    get_resp = {"/rest/owner": resp}
    findings = await mod.run(_surface(), _mock_platform(get_responses=get_resp))
    owner_findings = [f for f in findings if "/rest/owner" in f.title]
    assert len(owner_findings) == 1
    assert owner_findings[0].severity == Severity.HIGH
    assert owner_findings[0].owasp_id == OWASPCategory.ASI03


@pytest.mark.asyncio
async def test_n8n_credentials_idor_detected():
    """GET /api/v1/credentials/1 returns 200 → IDOR MEDIUM finding for n8n credential."""
    mod = PrivilegeAbuseModule()
    resp = _resp(200, {"id": "1", "name": "openai", "credentialType": "openAiApi"})
    get_resp = {"/api/v1/credentials/1": resp}
    findings = await mod.run(_surface(), _mock_platform(get_responses=get_resp))
    idor = [f for f in findings if "IDOR" in f.title]
    assert len(idor) == 1
    assert idor[0].severity == Severity.MEDIUM
    assert idor[0].cwe_id == "CWE-639"
    assert "/api/v1/credentials/1" in idor[0].evidence


# ── Dify credential exposure ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_dify_model_providers_exposed():
    """GET /console/api/workspaces/current/model-providers → CRITICAL finding."""
    mod = PrivilegeAbuseModule()
    resp = _resp(200, [{"provider": "openai", "token": "****"}])
    get_resp = {"/console/api/workspaces/current/model-providers": resp}
    findings = await mod.run(_surface(), _mock_platform(get_responses=get_resp))
    dify = [f for f in findings if "model-providers" in f.title]
    assert len(dify) == 1
    assert dify[0].severity == Severity.CRITICAL
    assert dify[0].owasp_id == OWASPCategory.ASI03


@pytest.mark.asyncio
async def test_dify_apikey_exposed():
    """GET /console/api/workspaces/current/apikey → CRITICAL finding."""
    mod = PrivilegeAbuseModule()
    resp = _resp(200, {"api_key": "app-abc123"})
    get_resp = {"/console/api/workspaces/current/apikey": resp}
    findings = await mod.run(_surface(), _mock_platform(get_responses=get_resp))
    dify = [f for f in findings if "apikey" in f.title]
    assert len(dify) == 1
    assert dify[0].severity == Severity.CRITICAL
    assert dify[0].owasp_id == OWASPCategory.ASI03


@pytest.mark.asyncio
async def test_dify_endpoints_html_filtered():
    """HTML response for Dify endpoints → no finding (SPA catch-all)."""
    mod = PrivilegeAbuseModule()
    html_resp = _resp(200, content_type="text/html")
    html_resp.text = "<html></html>"
    get_resp = {
        "/console/api/workspaces/current/model-providers": html_resp,
        "/console/api/workspaces/current/apikey": html_resp,
    }
    findings = await mod.run(_surface(), _mock_platform(get_responses=get_resp))
    assert not any("model-providers" in f.title or "apikey" in f.title for f in findings)


# ── LangGraph sensitive endpoints ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_langgraph_assistants_exposed():
    """GET /assistants returns 200 → HIGH finding for LangGraph assistant registry."""
    mod = PrivilegeAbuseModule()
    resp = _resp(200, [{"assistant_id": "a1", "name": "research-agent"}])
    get_resp = {"/assistants": resp}
    findings = await mod.run(_surface(), _mock_platform(get_responses=get_resp))
    lg = [f for f in findings if "/assistants" in f.title]
    assert len(lg) == 1
    assert lg[0].severity == Severity.HIGH
    assert lg[0].owasp_id == OWASPCategory.ASI03


@pytest.mark.asyncio
async def test_langgraph_crons_exposed():
    """GET /crons returns 200 → HIGH finding for LangGraph scheduled tasks."""
    mod = PrivilegeAbuseModule()
    resp = _resp(200, [{"cron_id": "c1", "schedule": "0 * * * *"}])
    get_resp = {"/crons": resp}
    findings = await mod.run(_surface(), _mock_platform(get_responses=get_resp))
    lg = [f for f in findings if "/crons" in f.title]
    assert len(lg) == 1
    assert lg[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_langgraph_store_namespaces_exposed():
    """GET /store/namespaces returns 200 → HIGH finding for LangGraph persistent store."""
    mod = PrivilegeAbuseModule()
    resp = _resp(200, ["namespace-1", "user-data"])
    get_resp = {"/store/namespaces": resp}
    findings = await mod.run(_surface(), _mock_platform(get_responses=get_resp))
    lg = [f for f in findings if "/store/namespaces" in f.title]
    assert len(lg) == 1
    assert lg[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_langgraph_threads_exposed():
    """GET /threads returns 200 → HIGH finding for LangGraph thread history."""
    mod = PrivilegeAbuseModule()
    resp = _resp(200, [{"thread_id": "t1", "created_at": "2024-01-01"}])
    get_resp = {"/threads": resp}
    findings = await mod.run(_surface(), _mock_platform(get_responses=get_resp))
    lg = [f for f in findings if "/threads" in f.title]
    assert len(lg) == 1
    assert lg[0].severity == Severity.HIGH
