"""Tests for ASI02 ToolMisuseModule."""
import pytest
from unittest.mock import AsyncMock, MagicMock

from condor.core.models import AgentSurface, OWASPCategory, Severity
from condor.modules.asi02_tool_misuse import ToolMisuseModule


def _surface(**kwargs) -> AgentSurface:
    defaults = {"platform": "flowise", "base_url": "http://localhost:3000"}
    defaults.update(kwargs)
    return AgentSurface(**defaults)


def _mock_platform(responses: dict | None = None) -> MagicMock:
    """Return a mock platform that returns 404 for all requests by default."""
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


def test_module_metadata():
    m = ToolMisuseModule()
    assert m.owasp_id == OWASPCategory.ASI02
    assert m.name == "tool-misuse"


@pytest.mark.asyncio
async def test_empty_surface_no_findings_on_404():
    mod = ToolMisuseModule()
    surface = _surface()
    platform = _mock_platform()
    findings = await mod.run(surface, platform)
    assert findings == []


@pytest.mark.asyncio
async def test_generic_probe_finding_when_no_tools():
    mod = ToolMisuseModule()
    surface = _surface()

    resp_200 = MagicMock(status_code=200, text='{"result": 2}', content=b'{"result": 2}')
    platform = _mock_platform({
        "/api/v1/tools/execute": resp_200,
    })

    findings = await mod.run(surface, platform)
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert findings[0].owasp_id == OWASPCategory.ASI02
    assert "without authentication" in findings[0].title


@pytest.mark.asyncio
async def test_credential_exposed_in_tool_config():
    mod = ToolMisuseModule()
    tool_with_creds = {
        "name": "openai-tool",
        "apiKey": "sk-supersecretkey1234",
    }
    surface = _surface(tools=[tool_with_creds])
    platform = _mock_platform()

    findings = await mod.run(surface, platform)
    cred_findings = [f for f in findings if "Credential exposed" in f.title]
    assert len(cred_findings) == 1
    assert cred_findings[0].severity == Severity.CRITICAL
    assert "openai-tool" in cred_findings[0].title
    assert "apiKey" in cred_findings[0].title


@pytest.mark.asyncio
async def test_source_code_exposed():
    mod = ToolMisuseModule()
    tool_with_code = {
        "name": "custom-tool",
        "func": "async function run(input) { return fetch(input.url).then(r => r.text()); }",
    }
    surface = _surface(tools=[tool_with_code])
    platform = _mock_platform()

    findings = await mod.run(surface, platform)
    code_findings = [f for f in findings if "source code exposed" in f.title]
    assert len(code_findings) == 1
    assert code_findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_path_traversal_confirmed():
    mod = ToolMisuseModule()
    tool = {
        "name": "file-reader",
        "inputParams": [{"name": "filePath", "type": "string"}],
    }
    surface = _surface(tools=[tool])

    resp_passwd = MagicMock(
        status_code=200,
        text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:",
        content=b"root:x:0:0:",
    )
    platform = _mock_platform({"/api/v1/node-load-method/file-reader": resp_passwd})

    findings = await mod.run(surface, platform)
    trav = [f for f in findings if "Path traversal" in f.title]
    assert len(trav) == 1
    assert trav[0].severity == Severity.CRITICAL
    assert trav[0].confidence == 95


@pytest.mark.asyncio
async def test_ssrf_confirmed():
    mod = ToolMisuseModule()
    tool = {
        "name": "http-tool",
        "inputParams": [{"name": "url", "type": "string"}],
    }
    surface = _surface(tools=[tool])

    resp_meta = MagicMock(
        status_code=200,
        text="ami-id\ninstance-id\nlocal-hostname",
        content=b"ami-id",
    )
    platform = _mock_platform({"/api/v1/node-load-method/http-tool": resp_meta})

    findings = await mod.run(surface, platform)
    ssrf = [f for f in findings if "SSRF via tool URL" in f.title]
    assert len(ssrf) == 1
    assert ssrf[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_potential_ssrf_medium():
    mod = ToolMisuseModule()
    tool = {
        "name": "web-tool",
        "inputParams": [{"name": "url", "type": "string"}],
    }
    surface = _surface(tools=[tool])

    resp_ok = MagicMock(
        status_code=200,
        text="some generic response body here",
        content=b"some generic response body here",
    )
    platform = _mock_platform({"/api/v1/node-load-method/web-tool": resp_ok})

    findings = await mod.run(surface, platform)
    pot_ssrf = [f for f in findings if "Potential SSRF" in f.title]
    assert len(pot_ssrf) == 1
    assert pot_ssrf[0].severity == Severity.MEDIUM
    assert pot_ssrf[0].confidence == 60


@pytest.mark.asyncio
async def test_ssti_detected():
    mod = ToolMisuseModule()
    tool = {
        "name": "template-tool",
        "inputParams": [{"name": "input", "type": "string"}],
    }
    surface = _surface(tools=[tool])

    resp_ssti = MagicMock(
        status_code=200,
        text='{"result": "49"}',
        content=b'{"result": "49"}',
    )
    platform = _mock_platform({"/api/v1/node-load-method/template-tool": resp_ssti})

    findings = await mod.run(surface, platform)
    ssti = [f for f in findings if "SSTI" in f.title]
    assert len(ssti) == 1
    assert ssti[0].severity == Severity.HIGH
    assert "template-tool" in ssti[0].title


@pytest.mark.asyncio
async def test_k8s_ssrf_confirmed():
    mod = ToolMisuseModule()
    tool = {
        "name": "http-tool",
        "inputParams": [{"name": "url", "type": "string"}],
    }
    surface = _surface(tools=[tool])

    # Kubernetes API server returns 401 Unauthorized with JSON body containing "kind"
    resp_k8s = MagicMock(
        status_code=200,
        text='{"kind": "Status", "apiVersion": "v1", "status": "Failure", "message": "Unauthorized"}',
        content=b'{"kind": "Status", "apiVersion": "v1"}',
    )
    platform = _mock_platform({"/api/v1/node-load-method/http-tool": resp_k8s})

    findings = await mod.run(surface, platform)
    ssrf = [f for f in findings if "SSRF via tool URL" in f.title]
    assert len(ssrf) == 1
    assert ssrf[0].severity == Severity.CRITICAL
