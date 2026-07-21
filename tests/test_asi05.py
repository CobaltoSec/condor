"""Tests for ASI05 CodeExecutionModule."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from condor.core.models import AgentSurface, OWASPCategory, Severity
from condor.modules.asi05_code_exec import CodeExecutionModule


def _surface(**kwargs) -> AgentSurface:
    defaults = {"platform": "flowise", "base_url": "http://localhost:3000"}
    defaults.update(kwargs)
    return AgentSurface(**defaults)


resp_404 = MagicMock(status_code=404, text="", content=b"")
resp_404.headers = {"content-type": "application/json"}


def _resp_200(text: str) -> MagicMock:
    r = MagicMock(status_code=200, text=text, content=text.encode())
    r.headers = {"content-type": "application/json"}
    return r


def _resp_html(text: str = "<html><body>Not found</body></html>") -> MagicMock:
    r = MagicMock(status_code=200, text=text, content=text.encode())
    r.headers = {"content-type": "text/html; charset=utf-8"}
    return r


# ── metadata ─────────────────────────────────────────────────────────────────


def test_module_metadata():
    m = CodeExecutionModule()
    assert m.name == "code-execution"
    assert m.owasp_id == OWASPCategory.ASI05
    assert "ASI05" in m.description


# ── baseline ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_no_findings_all_404():
    mod = CodeExecutionModule()
    plat = MagicMock()
    plat.post = AsyncMock(return_value=resp_404)
    findings = await mod.run(_surface(), plat)
    assert findings == []


# ── Flowise ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_flowise_rce_cmd_confirmed():
    """cmd probe returns command output → CRITICAL, confidence=98."""
    mod = CodeExecutionModule()
    plat = MagicMock()

    async def _post(path, **kw):
        code = (kw.get("json") or {}).get("code", "")
        if "execSync" in code:
            return _resp_200("uid=0(root) gid=0(root) groups=0(root)")
        return resp_404

    plat.post = _post
    findings = await mod.run(_surface(), plat)
    rce = [f for f in findings if "confirmed" in f.title]
    assert len(rce) >= 1
    assert rce[0].severity == Severity.CRITICAL
    assert rce[0].confidence == 98


@pytest.mark.asyncio
async def test_flowise_rce_os_confirmed():
    """cmd probe no indicators; os probe returns platform string → CRITICAL, confidence=95."""
    mod = CodeExecutionModule()
    plat = MagicMock()

    async def _post(path, **kw):
        code = (kw.get("json") or {}).get("code", "")
        if "execSync" in code:
            return _resp_200("ok")       # no cmd/os indicators
        if "platform()" in code:
            return _resp_200("linux")
        return resp_404

    plat.post = _post
    findings = await mod.run(_surface(), plat)
    rce = [f for f in findings if "code execution" in f.title.lower()]
    assert len(rce) >= 1
    assert rce[0].severity == Severity.CRITICAL
    assert rce[0].confidence == 95


@pytest.mark.asyncio
async def test_flowise_rce_os_unconfirmed():
    """cmd no indicators; os probe 200 but no os keywords → no finding (FP prevention)."""
    mod = CodeExecutionModule()
    plat = MagicMock()

    async def _post(path, **kw):
        code = (kw.get("json") or {}).get("code", "")
        if "execSync" in code:
            return _resp_200("ok")
        if "platform()" in code:
            return _resp_200("[]")  # Flowise node-load-method returns empty list, not OS name
        return resp_404

    plat.post = _post
    findings = await mod.run(_surface(), plat)
    rce = [f for f in findings if "code execution" in f.title.lower()]
    # No finding — 200 with no OS indicators means endpoint loaded schema, not executed code
    assert len(rce) == 0


@pytest.mark.asyncio
async def test_flowise_timing_probe():
    """cmd no indicators + os 404 + timing 200 with elapsed >= 0.25 → HIGH."""
    mod = CodeExecutionModule()
    plat = MagicMock()

    async def _post(path, **kw):
        code = (kw.get("json") or {}).get("code", "")
        if "execSync" in code:
            return _resp_200("ok")   # no cmd/os indicators
        if "platform()" in code:
            return resp_404          # os probe fails → falls to timing
        if "setTimeout" in code:
            return _resp_200("42")
        return resp_404

    plat.post = _post

    # 3 flowise endpoints × 2 monotonic calls each = 6 calls
    monotonic_values = [i * 0.5 for i in range(12)]
    with patch("condor.modules.asi05_code_exec.time") as mock_time:
        mock_time.monotonic.side_effect = monotonic_values
        findings = await mod.run(_surface(), plat)

    timing = [f for f in findings if "blind" in f.title.lower() or "timing" in f.title.lower()]
    assert len(timing) >= 1
    assert timing[0].severity == Severity.HIGH


# ── AutoGen ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_autogen_cmd_confirmed():
    """AutoGen cmd probe returns 'uid=' → CRITICAL, confidence=98."""
    mod = CodeExecutionModule()
    plat = MagicMock()

    async def _post(path, **kw):
        src = (kw.get("json") or {}).get("source_code", "")
        if "check_output" in src:
            return _resp_200("uid=1000(user) gid=1000(user)")
        return resp_404

    plat.post = _post
    findings = await mod.run(_surface(), plat)
    rce = [f for f in findings if "confirmed" in f.title and "AutoGen" in (f.description or "")]
    assert len(rce) >= 1
    assert rce[0].severity == Severity.CRITICAL
    assert rce[0].confidence == 98


@pytest.mark.asyncio
async def test_autogen_os_fallback():
    """AutoGen cmd no indicator; os probe returns a path → CRITICAL, confidence=95."""
    mod = CodeExecutionModule()
    plat = MagicMock()

    async def _post(path, **kw):
        src = (kw.get("json") or {}).get("source_code", "")
        if "check_output" in src:
            return _resp_200("ok")           # no cmd indicator
        if "getcwd" in src:
            return _resp_200("/app/server")  # path indicator
        return resp_404

    plat.post = _post
    findings = await mod.run(_surface(), plat)
    rce = [f for f in findings if "AutoGen" in (f.description or "")]
    assert len(rce) >= 1
    assert rce[0].severity == Severity.CRITICAL
    assert rce[0].confidence == 95


# ── Langflow ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_langflow_cmd_confirmed():
    """Langflow cmd probe returns 'uid=' → CRITICAL, confidence=98."""
    mod = CodeExecutionModule()
    plat = MagicMock()

    async def _post(path, **kw):
        code = (kw.get("json") or {}).get("code", "")
        if "check_output" in code:
            return _resp_200("uid=0(root)")
        return resp_404

    plat.post = _post
    findings = await mod.run(_surface(), plat)
    rce = [f for f in findings if "confirmed" in f.title and "Langflow" in (f.description or "")]
    assert len(rce) >= 1
    assert rce[0].severity == Severity.CRITICAL
    assert rce[0].confidence == 98


@pytest.mark.asyncio
async def test_langflow_print_confirmed():
    """Langflow cmd no indicator; print probe returns 'condor' in response → HIGH, confidence=85."""
    mod = CodeExecutionModule()
    plat = MagicMock()

    async def _post(path, **kw):
        code = (kw.get("json") or {}).get("code", "")
        if "check_output" in code:
            return _resp_200("ok")       # no cmd indicator
        if "print" in code and "condor" in code:
            return _resp_200("condor")
        return resp_404

    plat.post = _post
    findings = await mod.run(_surface(), plat)
    reachable = [f for f in findings if "reachable" in f.title.lower()]
    assert len(reachable) >= 1
    assert reachable[0].severity == Severity.HIGH
    assert reachable[0].confidence == 85


# ── edge cases ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_html_response_filtered():
    """200 with content-type text/html is rejected by _is_api_response → no findings."""
    mod = CodeExecutionModule()
    plat = MagicMock()
    plat.post = AsyncMock(return_value=_resp_html("uid=0(root) linux daemon"))
    findings = await mod.run(_surface(), plat)
    assert findings == []


@pytest.mark.asyncio
async def test_exception_swallowed():
    """Exceptions in platform.post are swallowed → empty findings list, no crash."""
    mod = CodeExecutionModule()
    plat = MagicMock()
    plat.post = AsyncMock(side_effect=Exception("connection refused"))
    findings = await mod.run(_surface(), plat)
    assert findings == []


# ── Open WebUI functions ──────────────────────────────────────────────────────


# ── Letta /v1/tools/run ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_letta_tools_run_cmd_confirmed():
    """POST /v1/tools/run returns 'uid=' → CRITICAL RCE confirmed, confidence=98."""
    mod = CodeExecutionModule()
    plat = MagicMock()

    async def _post(path, **kw):
        if path == "/v1/tools/run":
            src = (kw.get("json") or {}).get("source_code", "")
            if "popen" in src:
                return _resp_200('{"return_value": "uid=0(root) gid=0(root) groups=0(root)\\n"}')
        return resp_404

    plat.post = _post
    findings = await mod.run(_surface(), plat)
    letta = [f for f in findings if "Letta" in f.title and "confirmed" in f.title]
    assert len(letta) == 1
    assert letta[0].severity == Severity.CRITICAL
    assert letta[0].confidence == 98
    assert letta[0].cwe_id == "CWE-94"


@pytest.mark.asyncio
async def test_letta_tools_run_path_fallback():
    """cmd probe 200 no uid → path probe returns path → CRITICAL, confidence=90."""
    mod = CodeExecutionModule()
    plat = MagicMock()

    async def _post(path, **kw):
        if path == "/v1/tools/run":
            src = (kw.get("json") or {}).get("source_code", "")
            if "popen" in src:
                return _resp_200('{"return_value": "ok"}')
            if "getcwd" in src:
                return _resp_200('{"return_value": "/app/server"}')
        return resp_404

    plat.post = _post
    findings = await mod.run(_surface(), plat)
    letta = [f for f in findings if "Letta" in f.title]
    assert len(letta) == 1
    assert letta[0].severity == Severity.CRITICAL
    assert letta[0].confidence == 90


@pytest.mark.asyncio
async def test_letta_tools_run_accepted_no_indicators():
    """Both probes return 200 with no recognizable output → CRITICAL, confidence=80."""
    mod = CodeExecutionModule()
    plat = MagicMock()

    async def _post(path, **kw):
        if path == "/v1/tools/run":
            return _resp_200('{"return_value": null}')
        return resp_404

    plat.post = _post
    findings = await mod.run(_surface(), plat)
    letta = [f for f in findings if "Letta" in f.title]
    assert len(letta) == 1
    assert letta[0].severity == Severity.CRITICAL
    assert letta[0].confidence == 80


@pytest.mark.asyncio
async def test_letta_tools_run_401_no_finding():
    """POST /v1/tools/run → 401 → no finding (auth enforced)."""
    mod = CodeExecutionModule()
    plat = MagicMock()

    async def _post(path, **kw):
        if path == "/v1/tools/run":
            r = MagicMock(status_code=401, text="Unauthorized")
            r.headers = {"content-type": "application/json"}
            return r
        return resp_404

    plat.post = _post
    findings = await mod.run(_surface(), plat)
    letta = [f for f in findings if "Letta" in (f.title + (f.description or ""))]
    assert letta == []


@pytest.mark.asyncio
async def test_letta_tools_run_html_filtered():
    """POST /v1/tools/run returns HTML → _is_api_response filters it → no finding."""
    mod = CodeExecutionModule()
    plat = MagicMock()

    async def _post(path, **kw):
        if path == "/v1/tools/run":
            return _resp_html("uid=0(root) linux daemon")
        return resp_404

    plat.post = _post
    findings = await mod.run(_surface(), plat)
    letta = [f for f in findings if "Letta" in (f.title + (f.description or ""))]
    assert letta == []


@pytest.mark.asyncio
async def test_owui_function_creation_critical():
    """POST /api/v1/functions returns 201 → CRITICAL function creation without auth."""
    mod = CodeExecutionModule()
    plat = MagicMock()

    async def _post(path, **kw):
        if path == "/api/v1/functions":
            r = MagicMock(status_code=201, text='{"id": "fn-1", "name": "condor-probe"}', content=b'{}')
            r.headers = {"content-type": "application/json"}
            r.json.return_value = {"id": "fn-1", "name": "condor-probe"}
            return r
        return resp_404

    async def _delete(path, **kw):
        return resp_404

    plat.post = _post
    plat.delete = _delete
    findings = await mod.run(_surface(), plat)
    owui = [f for f in findings if "function creation" in f.title]
    assert len(owui) == 1
    assert owui[0].severity == Severity.CRITICAL
    assert owui[0].confidence == 95
    assert owui[0].cwe_id == "CWE-306"


@pytest.mark.asyncio
async def test_owui_function_endpoint_accessible_high():
    """POST /api/v1/functions returns 400 (no auth) → HIGH accessible finding."""
    mod = CodeExecutionModule()
    plat = MagicMock()

    async def _post(path, **kw):
        if path == "/api/v1/functions":
            r = MagicMock(status_code=400, text='{"detail": "validation error"}', content=b'{}')
            r.headers = {"content-type": "application/json"}
            return r
        return resp_404

    async def _delete(path, **kw):
        return resp_404

    plat.post = _post
    plat.delete = _delete
    findings = await mod.run(_surface(), plat)
    owui = [f for f in findings if "function endpoint accessible" in f.title]
    assert len(owui) == 1
    assert owui[0].severity == Severity.HIGH
    assert owui[0].confidence == 70


@pytest.mark.asyncio
async def test_owui_function_401_no_finding():
    """POST /api/v1/functions returns 401 → no finding (auth enforced)."""
    mod = CodeExecutionModule()
    plat = MagicMock()

    async def _post(path, **kw):
        if path == "/api/v1/functions":
            r = MagicMock(status_code=401, text="Unauthorized", content=b"Unauthorized")
            r.headers = {"content-type": "application/json"}
            return r
        return resp_404

    async def _delete(path, **kw):
        return resp_404

    plat.post = _post
    plat.delete = _delete
    findings = await mod.run(_surface(), plat)
    owui = [f for f in findings if "function" in f.title.lower() and "Open WebUI" in f.description]
    assert owui == []


@pytest.mark.asyncio
async def test_owui_function_html_filtered():
    """POST /api/v1/functions returns HTML (SPA catch-all) → no finding."""
    mod = CodeExecutionModule()
    plat = MagicMock()

    async def _post(path, **kw):
        if path == "/api/v1/functions":
            r = MagicMock(status_code=200, text="<html><body></body></html>", content=b"<html>")
            r.headers = {"content-type": "text/html; charset=utf-8"}
            return r
        return resp_404

    async def _delete(path, **kw):
        return resp_404

    plat.post = _post
    plat.delete = _delete
    findings = await mod.run(_surface(), plat)
    owui = [f for f in findings if "/api/v1/functions" in f.endpoint]
    assert owui == []


# ── Hayhooks pipeline execution ───────────────────────────────────────────────


def _hayhooks_surface(**kwargs) -> AgentSurface:
    defaults = {"platform": "hayhooks", "base_url": "http://localhost:1416"}
    defaults.update(kwargs)
    return AgentSurface(**defaults)


@pytest.mark.asyncio
async def test_hayhooks_pipeline_exec_200_critical():
    """Pipeline in surface.flows, POST /pipelines/name/run → 200 → CRITICAL."""
    mod = CodeExecutionModule()
    plat = MagicMock()

    async def _post(path, **kw):
        if path == "/pipelines/my-pipeline/run":
            return _resp_200('{"result": "ok"}')
        return resp_404

    plat.post = _post
    surface = _hayhooks_surface(flows=[{"name": "my-pipeline"}])
    findings = await mod.run(surface, plat)
    hh = [f for f in findings if "pipeline" in f.title.lower() and f.cwe_id == "CWE-306"]
    assert len(hh) >= 1
    assert hh[0].severity == Severity.CRITICAL
    assert hh[0].confidence == 90
    assert hh[0].cwe_id == "CWE-306"


@pytest.mark.asyncio
async def test_hayhooks_pipeline_exec_422_high():
    """POST /pipelines/name/run → 422 → HIGH (endpoint reachable, payload rejected)."""
    mod = CodeExecutionModule()
    plat = MagicMock()

    async def _post(path, **kw):
        if path == "/pipelines/my-pipeline/run":
            r = MagicMock(status_code=422, text='{"detail": "validation error"}', content=b"{}")
            r.headers = {"content-type": "application/json"}
            return r
        return resp_404

    plat.post = _post
    surface = _hayhooks_surface(flows=[{"name": "my-pipeline"}])
    findings = await mod.run(surface, plat)
    hh = [f for f in findings if "pipeline" in f.title.lower() and f.cwe_id == "CWE-306"]
    assert len(hh) >= 1
    assert hh[0].severity == Severity.HIGH
    assert hh[0].confidence == 75
    assert "422" in hh[0].evidence


@pytest.mark.asyncio
async def test_hayhooks_pipeline_exec_401_no_finding():
    """POST /pipelines/name/run → 401 → no finding (auth enforced)."""
    mod = CodeExecutionModule()
    plat = MagicMock()

    async def _post(path, **kw):
        if path == "/pipelines/my-pipeline/run":
            r = MagicMock(status_code=401, text="Unauthorized", content=b"Unauthorized")
            r.headers = {"content-type": "application/json"}
            return r
        return resp_404

    plat.post = _post
    surface = _hayhooks_surface(flows=[{"name": "my-pipeline"}])
    findings = await mod.run(surface, plat)
    hh = [f for f in findings if "Hayhooks" in f.description]
    assert hh == []


@pytest.mark.asyncio
async def test_hayhooks_pipeline_exec_empty_flows_fetches_list():
    """surface.flows empty → GET /pipelines returns list → probe → CRITICAL finding."""
    mod = CodeExecutionModule()
    plat = MagicMock()

    async def _get(path, **kw):
        if path == "/pipelines":
            r = MagicMock(status_code=200, text='[{"name": "qa-pipeline"}]', content=b'[]')
            r.headers = {"content-type": "application/json"}
            r.json.return_value = [{"name": "qa-pipeline"}]
            return r
        return resp_404

    async def _post(path, **kw):
        if path == "/pipelines/qa-pipeline/run":
            return _resp_200('{"result": "ok"}')
        return resp_404

    plat.get = _get
    plat.post = _post
    surface = _hayhooks_surface()  # flows=[]
    findings = await mod.run(surface, plat)
    hh = [f for f in findings if "pipeline" in f.title.lower() and f.cwe_id == "CWE-306"]
    assert len(hh) >= 1
    assert hh[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_hayhooks_no_pipelines_no_finding():
    """surface.flows empty AND GET /pipelines returns empty list → no finding."""
    mod = CodeExecutionModule()
    plat = MagicMock()

    async def _get(path, **kw):
        if path == "/pipelines":
            r = MagicMock(status_code=200, text="[]", content=b"[]")
            r.headers = {"content-type": "application/json"}
            r.json.return_value = []
            return r
        return resp_404

    plat.get = _get
    plat.post = AsyncMock(return_value=resp_404)
    surface = _hayhooks_surface()
    findings = await mod.run(surface, plat)
    hh = [f for f in findings if f.cwe_id == "CWE-306" and "pipeline" in f.title.lower()]
    assert hh == []


@pytest.mark.asyncio
async def test_hayhooks_older_url_fallback_critical():
    """POST /pipelines/name/run → 404 → fallback POST /name/run → 200 → CRITICAL."""
    mod = CodeExecutionModule()
    plat = MagicMock()

    async def _post(path, **kw):
        if path == "/pipelines/my-pipeline/run":
            r = MagicMock(status_code=404, text="not found", content=b"not found")
            r.headers = {"content-type": "application/json"}
            return r
        if path == "/my-pipeline/run":
            return _resp_200('{"result": "ok"}')
        return resp_404

    plat.post = _post
    surface = _hayhooks_surface(flows=[{"name": "my-pipeline"}])
    findings = await mod.run(surface, plat)
    hh = [f for f in findings if "pipeline" in f.title.lower() and f.cwe_id == "CWE-306"]
    assert len(hh) >= 1
    assert hh[0].severity == Severity.CRITICAL
    assert "/my-pipeline/run" in hh[0].endpoint


# ── Dify sandbox ──────────────────────────────────────────────────────────────


def _dify_surface(**kw) -> AgentSurface:
    return AgentSurface(platform="dify", base_url="http://localhost:5001", **kw)


def _make_sandbox_client(health_ok: bool = True, exec_output: str | None = "condor-sandbox-probe"):
    """Return a mock httpx.AsyncClient that simulates the Dify sandbox."""
    health_resp = MagicMock()
    health_resp.status_code = 200 if health_ok else 503
    health_resp.text = '"ok"' if health_ok else ""

    run_resp = MagicMock()
    if exec_output is not None:
        run_resp.status_code = 200
        run_resp.json.return_value = {"code": 0, "message": "success", "data": {"stdout": exec_output + "\n", "error": ""}}
    else:
        run_resp.status_code = 403
        run_resp.json.return_value = {"code": 403, "message": "forbidden"}

    client = AsyncMock()
    client.get = AsyncMock(return_value=health_resp)
    client.post = AsyncMock(return_value=run_resp)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client


@pytest.mark.asyncio
async def test_dify_sandbox_critical_and_high():
    """Sandbox reachable + default key accepted → HIGH (port exposed) + CRITICAL (exec)."""
    mod = CodeExecutionModule()
    plat = MagicMock()
    plat.base_url = "http://localhost:5001"
    plat.get = AsyncMock(return_value=resp_404)
    plat.post = AsyncMock(return_value=resp_404)

    mock_client = _make_sandbox_client(health_ok=True, exec_output="condor-sandbox-probe")
    with patch("condor.modules.asi05_code_exec.httpx.AsyncClient", return_value=mock_client):
        findings = await mod._check_dify_sandbox(plat)

    severities = {f.severity for f in findings}
    assert Severity.HIGH in severities
    assert Severity.CRITICAL in severities
    assert all(f.cwe_id == "CWE-306" for f in findings)


@pytest.mark.asyncio
async def test_dify_sandbox_high_only_when_exec_rejected():
    """Sandbox reachable but all API keys rejected (403) → HIGH only, no CRITICAL."""
    mod = CodeExecutionModule()
    plat = MagicMock()
    plat.base_url = "http://localhost:5001"
    plat.get = AsyncMock(return_value=resp_404)
    plat.post = AsyncMock(return_value=resp_404)

    mock_client = _make_sandbox_client(health_ok=True, exec_output=None)
    with patch("condor.modules.asi05_code_exec.httpx.AsyncClient", return_value=mock_client):
        findings = await mod._check_dify_sandbox(plat)

    assert any(f.severity == Severity.HIGH for f in findings)
    assert not any(f.severity == Severity.CRITICAL for f in findings)


@pytest.mark.asyncio
async def test_dify_sandbox_not_reachable():
    """Sandbox port unreachable (connection refused) → no findings."""
    mod = CodeExecutionModule()
    plat = MagicMock()
    plat.base_url = "http://localhost:5001"
    plat.get = AsyncMock(return_value=resp_404)
    plat.post = AsyncMock(return_value=resp_404)

    mock_client = _make_sandbox_client(health_ok=False)
    with patch("condor.modules.asi05_code_exec.httpx.AsyncClient", return_value=mock_client):
        findings = await mod._check_dify_sandbox(plat)

    assert findings == []


@pytest.mark.asyncio
async def test_dify_sandbox_via_run_surface_platform():
    """run() calls _check_dify_sandbox() when surface.platform == 'dify'."""
    mod = CodeExecutionModule()
    plat = MagicMock()
    plat.base_url = "http://localhost:5001"
    plat.get = AsyncMock(return_value=resp_404)
    plat.post = AsyncMock(return_value=resp_404)

    mock_client = _make_sandbox_client(health_ok=True, exec_output="/app")
    with patch("condor.modules.asi05_code_exec.httpx.AsyncClient", return_value=mock_client):
        findings = await mod.run(_dify_surface(), plat)

    sandbox_findings = [f for f in findings if "sandbox" in f.title.lower()]
    assert len(sandbox_findings) >= 1
