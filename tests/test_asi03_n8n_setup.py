"""Tests for n8n owner setup vulnerability probe (ASI03)."""
import pytest
from unittest.mock import MagicMock

from condor.core.models import AgentSurface, OWASPCategory, Severity
from condor.modules.asi03_privilege import PrivilegeAbuseModule


def _surface(**kwargs) -> AgentSurface:
    defaults = {"platform": "n8n", "base_url": "http://localhost:5678"}
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


def _mock_platform(get_responses=None, post_responses=None):
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
        return _resp(200)

    plat.get = _get
    plat.post = _post
    plat.delete = _delete
    return plat


_SETTINGS_FRESH = {
    "data": {
        "settingsMode": "public",
        "defaultLocale": "en",
        "userManagement": {
            "authenticationMethod": "email",
            "showSetupOnFirstLoad": True,
            "smtpSetup": False,
            "passwordMinLength": 8,
        },
    }
}

_SETTINGS_CONFIGURED = {
    "data": {
        "settingsMode": "public",
        "defaultLocale": "en",
        "userManagement": {
            "authenticationMethod": "email",
            "showSetupOnFirstLoad": False,
            "smtpSetup": False,
            "passwordMinLength": 8,
        },
    }
}


@pytest.mark.asyncio
async def test_n8n_owner_setup_fresh_instance_critical():
    """GET /rest/settings → showSetupOnFirstLoad=true → CRITICAL finding."""
    mod = PrivilegeAbuseModule()
    get_resp = {"/rest/settings": _resp(200, _SETTINGS_FRESH)}
    findings = await mod.run(_surface(), _mock_platform(get_responses=get_resp))
    setup = [f for f in findings if "owner account creation" in f.title]
    assert len(setup) == 1
    assert setup[0].severity == Severity.CRITICAL
    assert setup[0].owasp_id == OWASPCategory.ASI03
    assert setup[0].cwe_id == "CWE-306"
    assert setup[0].endpoint == "/rest/owner/setup"
    assert setup[0].confidence == 95


@pytest.mark.asyncio
async def test_n8n_owner_setup_configured_instance_no_finding():
    """GET /rest/settings → showSetupOnFirstLoad=false → no finding."""
    mod = PrivilegeAbuseModule()
    get_resp = {"/rest/settings": _resp(200, _SETTINGS_CONFIGURED)}
    findings = await mod.run(_surface(), _mock_platform(get_responses=get_resp))
    setup = [f for f in findings if "owner account creation" in f.title]
    assert setup == []


@pytest.mark.asyncio
async def test_n8n_owner_setup_html_response_filtered():
    """HTML response for /rest/settings → no finding (not n8n or SPA catch-all)."""
    mod = PrivilegeAbuseModule()
    html_resp = _resp(200, content_type="text/html")
    html_resp.text = "<html></html>"
    get_resp = {"/rest/settings": html_resp}
    findings = await mod.run(_surface(), _mock_platform(get_responses=get_resp))
    setup = [f for f in findings if "owner account creation" in f.title]
    assert setup == []


@pytest.mark.asyncio
async def test_n8n_owner_setup_settings_404_no_finding():
    """GET /rest/settings → 404 → no finding."""
    mod = PrivilegeAbuseModule()
    findings = await mod.run(_surface(), _mock_platform())
    setup = [f for f in findings if "owner account creation" in f.title]
    assert setup == []
