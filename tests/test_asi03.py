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
