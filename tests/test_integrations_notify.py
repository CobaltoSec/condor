"""Tests for Slack/Teams notification integrations."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from condor.core.models import Finding, OWASPCategory, Severity, ScanResult
from condor.integrations.notify import notify_slack, notify_teams


def _result(findings=None) -> ScanResult:
    return ScanResult(
        target="http://target:3000",
        platform="flowise",
        findings=findings or [],
        modules_run=["goal-hijack"],
    )


def _finding(severity=Severity.HIGH) -> Finding:
    return Finding(
        title="Test finding",
        severity=severity,
        owasp_id=OWASPCategory.ASI01,
        description="desc",
    )


@pytest.mark.asyncio
async def test_slack_posts_to_webhook():
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_resp)

    with patch("condor.integrations.notify.httpx.AsyncClient", return_value=mock_client):
        await notify_slack("https://hooks.slack.com/test", _result())

    mock_client.post.assert_called_once()
    _, kwargs = mock_client.post.call_args
    assert "text" in kwargs["json"]


@pytest.mark.asyncio
async def test_slack_message_contains_target():
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_resp)

    with patch("condor.integrations.notify.httpx.AsyncClient", return_value=mock_client):
        await notify_slack("https://hooks.slack.com/test", _result())

    _, kwargs = mock_client.post.call_args
    assert "target:3000" in kwargs["json"]["text"]


@pytest.mark.asyncio
async def test_slack_clean_scan_shows_ok():
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_resp)

    with patch("condor.integrations.notify.httpx.AsyncClient", return_value=mock_client):
        await notify_slack("https://hooks.slack.com/test", _result([]))

    _, kwargs = mock_client.post.call_args
    assert "No findings" in kwargs["json"]["text"]


@pytest.mark.asyncio
async def test_slack_critical_finding_shown():
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_resp)

    with patch("condor.integrations.notify.httpx.AsyncClient", return_value=mock_client):
        await notify_slack("https://hooks.slack.com/test", _result([_finding(Severity.CRITICAL)]))

    _, kwargs = mock_client.post.call_args
    assert "CRITICAL" in kwargs["json"]["text"]


@pytest.mark.asyncio
async def test_teams_posts_message_card():
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_resp)

    with patch("condor.integrations.notify.httpx.AsyncClient", return_value=mock_client):
        await notify_teams("https://outlook.office.com/webhook/test", _result())

    mock_client.post.assert_called_once()
    _, kwargs = mock_client.post.call_args
    assert kwargs["json"]["@type"] == "MessageCard"


@pytest.mark.asyncio
async def test_teams_critical_uses_red_theme():
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_resp)

    with patch("condor.integrations.notify.httpx.AsyncClient", return_value=mock_client):
        await notify_teams("https://webhook", _result([_finding(Severity.CRITICAL)]))

    _, kwargs = mock_client.post.call_args
    assert kwargs["json"]["themeColor"] == "FF0000"


@pytest.mark.asyncio
async def test_teams_clean_uses_green_theme():
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_resp)

    with patch("condor.integrations.notify.httpx.AsyncClient", return_value=mock_client):
        await notify_teams("https://webhook", _result([]))

    _, kwargs = mock_client.post.call_args
    assert kwargs["json"]["themeColor"] == "00CC00"


@pytest.mark.asyncio
async def test_teams_has_target_fact():
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_resp)

    with patch("condor.integrations.notify.httpx.AsyncClient", return_value=mock_client):
        await notify_teams("https://webhook", _result())

    _, kwargs = mock_client.post.call_args
    facts = kwargs["json"]["sections"][0]["facts"]
    fact_names = [f["name"] for f in facts]
    assert "Target" in fact_names
