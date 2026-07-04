"""Tests for ASI08 CascadingFailuresModule."""
import pytest
from unittest.mock import MagicMock

from condor.core.models import AgentSurface, OWASPCategory, Severity
from condor.modules.asi08_cascading import CascadingFailuresModule


def _surface(**kwargs) -> AgentSurface:
    defaults = {"platform": "flowise", "base_url": "http://localhost:3000"}
    defaults.update(kwargs)
    return AgentSurface(**defaults)


def _mock_platform(responses: dict | None = None) -> MagicMock:
    plat = MagicMock()
    resp_404 = MagicMock(status_code=404, text="Not Found", content=b"Not Found")
    resp_404.headers = {"content-type": "text/html"}

    async def _get(path, **kw):
        if responses and path in responses:
            return responses[path]
        return resp_404

    async def _delete(path, **kw):
        if responses and path in responses:
            return responses[path]
        return resp_404

    plat.get = _get
    plat.delete = _delete
    return plat


def _json_resp(status: int, data) -> MagicMock:
    import json as _json
    body = _json.dumps(data)
    r = MagicMock(status_code=status, text=body, content=body.encode())
    r.headers = {"content-type": "application/json"}
    r.json.return_value = data
    return r


def test_module_metadata():
    m = CascadingFailuresModule()
    assert m.owasp_id == OWASPCategory.ASI08
    assert m.name == "cascading-failures"


@pytest.mark.asyncio
async def test_no_findings_on_404():
    mod = CascadingFailuresModule()
    findings = await mod.run(_surface(), _mock_platform())
    assert findings == []


@pytest.mark.asyncio
async def test_rate_limit_missing_medium():
    mod = CascadingFailuresModule()
    resp = MagicMock(status_code=200, text="ok", content=b"ok")
    resp.headers = {"content-type": "application/json"}
    platform = _mock_platform({"/api/v1/prediction/condor-probe": resp})
    findings = await mod.run(_surface(), platform)
    rl = [f for f in findings if "No rate limiting" in f.title]
    assert len(rl) == 1
    assert rl[0].severity == Severity.MEDIUM
    assert rl[0].confidence == 70


@pytest.mark.asyncio
async def test_rate_limit_present_info():
    mod = CascadingFailuresModule()
    resp = MagicMock(status_code=429, text="too many requests", content=b"too many")
    resp.headers = {}
    platform = _mock_platform({"/api/v1/prediction/condor-probe": resp})
    findings = await mod.run(_surface(), platform)
    rl = [f for f in findings if "Rate limiting active" in f.title]
    assert len(rl) == 1
    assert rl[0].severity == Severity.INFO


@pytest.mark.asyncio
async def test_rate_limit_header_suppresses_finding():
    mod = CascadingFailuresModule()
    resp = MagicMock(status_code=200, text="ok", content=b"ok")
    resp.headers = {"content-type": "application/json", "x-ratelimit-limit": "100"}
    platform = _mock_platform({"/api/v1/prediction/condor-probe": resp})
    findings = await mod.run(_surface(), platform)
    rl = [f for f in findings if "No rate limiting" in f.title]
    assert rl == []


@pytest.mark.asyncio
async def test_task_queue_exposed_high():
    mod = CascadingFailuresModule()
    resp = _json_resp(200, [{"id": "job1"}, {"id": "job2"}])
    platform = _mock_platform({"/api/v1/queue": resp})
    findings = await mod.run(_surface(), platform)
    q = [f for f in findings if "task queue" in f.title]
    assert len(q) == 1
    assert q[0].severity == Severity.HIGH
    assert "2 queued tasks" in q[0].evidence


@pytest.mark.asyncio
async def test_task_queue_empty_still_high():
    mod = CascadingFailuresModule()
    resp = _json_resp(200, [])
    platform = _mock_platform({"/api/v1/queue": resp})
    findings = await mod.run(_surface(), platform)
    q = [f for f in findings if "task queue" in f.title]
    assert len(q) == 1
    assert q[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_job_cancellation_accepted_high():
    mod = CascadingFailuresModule()
    resp = MagicMock(status_code=200, text="deleted", content=b"deleted")
    resp.headers = {"content-type": "application/json"}
    platform = _mock_platform({"/api/v1/queue/condor-probe": resp})
    findings = await mod.run(_surface(), platform)
    c = [f for f in findings if "cancellation accepted" in f.title]
    assert len(c) == 1
    assert c[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_job_endpoint_accessible_medium():
    mod = CascadingFailuresModule()
    resp = _json_resp(404, {"error": "not found"})
    platform = _mock_platform({"/api/v1/queue/condor-probe": resp})
    findings = await mod.run(_surface(), platform)
    c = [f for f in findings if "accessible without auth" in f.title]
    assert len(c) == 1
    assert c[0].severity == Severity.MEDIUM
