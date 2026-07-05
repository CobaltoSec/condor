"""Tests for DefectDojo export integration."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch, call

from condor.core.models import Finding, OWASPCategory, Severity, ScanResult
from condor.integrations.defectdojo import export_to_defectdojo


def _result(findings=None) -> ScanResult:
    return ScanResult(
        target="http://target:3000",
        platform="flowise",
        findings=findings or [],
        modules_run=["goal-hijack"],
    )


def _finding(cwe_id=None) -> Finding:
    return Finding(
        title="Test RCE",
        severity=Severity.CRITICAL,
        owasp_id=OWASPCategory.ASI05,
        description="Remote code execution.",
        evidence="POST /exec → 200",
        endpoint="/api/v1/exec",
        cwe_id=cwe_id,
    )


def _make_client(product_exists=True):
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    def make_resp(data):
        r = MagicMock()
        r.raise_for_status = MagicMock()
        r.json.return_value = data
        return r

    product_resp = make_resp({"results": [{"id": 42}]} if product_exists else {"results": []})
    product_create_resp = make_resp({"id": 42})
    engagement_resp = make_resp({"id": 10})
    test_resp = make_resp({"id": 20})
    finding_resp = make_resp({"id": 100})

    calls = [product_resp]
    if not product_exists:
        calls.append(product_create_resp)
    calls += [engagement_resp, test_resp, finding_resp]

    mock_client.get = AsyncMock(return_value=product_resp)
    mock_client.post = AsyncMock(side_effect=
        ([] if product_exists else [product_create_resp]) + [engagement_resp, test_resp, finding_resp]
    )
    return mock_client


@pytest.mark.asyncio
async def test_export_creates_engagement_and_test():
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    def make_resp(data):
        r = MagicMock()
        r.raise_for_status = MagicMock()
        r.json.return_value = data
        return r

    mock_client.get = AsyncMock(return_value=make_resp({"results": [{"id": 5}]}))
    mock_client.post = AsyncMock(side_effect=[
        make_resp({"id": 10}),  # engagement
        make_resp({"id": 20}),  # test
        make_resp({"id": 100}), # finding
    ])

    with patch("condor.integrations.defectdojo.httpx.AsyncClient", return_value=mock_client):
        await export_to_defectdojo(_result([_finding()]), "http://dd:8080", "token", "MyProduct")

    assert mock_client.post.call_count == 3


@pytest.mark.asyncio
async def test_export_cwe_included_in_finding_payload():
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    captured_payloads = []

    def make_resp(data):
        r = MagicMock()
        r.raise_for_status = MagicMock()
        r.json.return_value = data
        return r

    async def mock_post(url, json=None, **kwargs):
        captured_payloads.append(json or {})
        if "engagements" in url:
            return make_resp({"id": 10})
        if "tests" in url:
            return make_resp({"id": 20})
        return make_resp({"id": 100})

    mock_client.get = AsyncMock(return_value=make_resp({"results": [{"id": 5}]}))
    mock_client.post = AsyncMock(side_effect=mock_post)

    with patch("condor.integrations.defectdojo.httpx.AsyncClient", return_value=mock_client):
        await export_to_defectdojo(_result([_finding("CWE-78")]), "http://dd:8080", "token", "Prod")

    finding_payload = captured_payloads[-1]
    assert finding_payload.get("cwe") == 78


@pytest.mark.asyncio
async def test_export_no_cwe_when_missing():
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    captured = []

    def make_resp(data):
        r = MagicMock()
        r.raise_for_status = MagicMock()
        r.json.return_value = data
        return r

    async def mock_post(url, json=None, **kwargs):
        captured.append(json or {})
        if "engagements" in url:
            return make_resp({"id": 10})
        if "tests" in url:
            return make_resp({"id": 20})
        return make_resp({"id": 100})

    mock_client.get = AsyncMock(return_value=make_resp({"results": [{"id": 5}]}))
    mock_client.post = AsyncMock(side_effect=mock_post)

    with patch("condor.integrations.defectdojo.httpx.AsyncClient", return_value=mock_client):
        await export_to_defectdojo(_result([_finding(None)]), "http://dd:8080", "token", "Prod")

    finding_payload = captured[-1]
    assert "cwe" not in finding_payload


@pytest.mark.asyncio
async def test_export_severity_mapped_correctly():
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    captured = []

    def make_resp(data):
        r = MagicMock()
        r.raise_for_status = MagicMock()
        r.json.return_value = data
        return r

    async def mock_post(url, json=None, **kwargs):
        captured.append(json or {})
        if "engagements" in url:
            return make_resp({"id": 10})
        if "tests" in url:
            return make_resp({"id": 20})
        return make_resp({"id": 100})

    mock_client.get = AsyncMock(return_value=make_resp({"results": [{"id": 5}]}))
    mock_client.post = AsyncMock(side_effect=mock_post)

    with patch("condor.integrations.defectdojo.httpx.AsyncClient", return_value=mock_client):
        await export_to_defectdojo(_result([_finding()]), "http://dd:8080", "token", "Prod")

    finding_payload = captured[-1]
    assert finding_payload["severity"] == "Critical"


@pytest.mark.asyncio
async def test_export_owasp_tag_included():
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    captured = []

    def make_resp(data):
        r = MagicMock()
        r.raise_for_status = MagicMock()
        r.json.return_value = data
        return r

    async def mock_post(url, json=None, **kwargs):
        captured.append(json or {})
        if "engagements" in url:
            return make_resp({"id": 10})
        if "tests" in url:
            return make_resp({"id": 20})
        return make_resp({"id": 100})

    mock_client.get = AsyncMock(return_value=make_resp({"results": [{"id": 5}]}))
    mock_client.post = AsyncMock(side_effect=mock_post)

    with patch("condor.integrations.defectdojo.httpx.AsyncClient", return_value=mock_client):
        await export_to_defectdojo(_result([_finding()]), "http://dd:8080", "token", "Prod")

    finding_payload = captured[-1]
    assert "ASI05" in finding_payload.get("tags", [])


@pytest.mark.asyncio
async def test_export_empty_findings_no_finding_post():
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    call_count = 0

    def make_resp(data):
        r = MagicMock()
        r.raise_for_status = MagicMock()
        r.json.return_value = data
        return r

    mock_client.get = AsyncMock(return_value=make_resp({"results": [{"id": 5}]}))
    mock_client.post = AsyncMock(side_effect=[
        make_resp({"id": 10}),
        make_resp({"id": 20}),
    ])

    with patch("condor.integrations.defectdojo.httpx.AsyncClient", return_value=mock_client):
        await export_to_defectdojo(_result([]), "http://dd:8080", "token", "Prod")

    assert mock_client.post.call_count == 2  # engagement + test only, no findings


@pytest.mark.asyncio
async def test_export_creates_product_when_missing():
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    def make_resp(data):
        r = MagicMock()
        r.raise_for_status = MagicMock()
        r.json.return_value = data
        return r

    mock_client.get = AsyncMock(return_value=make_resp({"results": []}))
    mock_client.post = AsyncMock(side_effect=[
        make_resp({"id": 99}),  # product creation
        make_resp({"id": 10}),  # engagement
        make_resp({"id": 20}),  # test
    ])

    with patch("condor.integrations.defectdojo.httpx.AsyncClient", return_value=mock_client):
        await export_to_defectdojo(_result([]), "http://dd:8080", "token", "NewProduct")

    assert mock_client.post.call_count == 3
