"""Slack and Teams webhook notifications for Condor scan results."""
from __future__ import annotations

import httpx

from ..core.models import ScanResult


async def notify_slack(webhook_url: str, result: ScanResult) -> None:
    counts = result.finding_count
    total = sum(counts.values())
    target = result.target
    platform = result.platform

    parts = [f"*Condor Scan Complete* — `{target}` ({platform})"]
    if total == 0:
        parts.append("✅ No findings")
    else:
        sev_line = " · ".join(
            f"{sev.upper()}: {n}"
            for sev in ("critical", "high", "medium", "low", "info")
            if (n := counts.get(sev, 0)) > 0
        )
        parts.append(f"⚠️ {total} finding(s): {sev_line}")

    payload = {"text": "\n".join(parts)}
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(webhook_url, json=payload)
        r.raise_for_status()


async def notify_teams(webhook_url: str, result: ScanResult) -> None:
    counts = result.finding_count
    total = sum(counts.values())
    target = result.target
    platform = result.platform

    if counts.get("critical", 0) > 0:
        theme_color = "FF0000"
    elif counts.get("high", 0) > 0:
        theme_color = "FF8C00"
    elif total > 0:
        theme_color = "FFA500"
    else:
        theme_color = "00CC00"

    facts = [{"name": "Target", "value": target}, {"name": "Platform", "value": platform}]
    for sev in ("critical", "high", "medium", "low", "info"):
        n = counts.get(sev, 0)
        if n > 0:
            facts.append({"name": sev.capitalize(), "value": str(n)})
    if total == 0:
        facts.append({"name": "Result", "value": "Clean — no findings"})

    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": theme_color,
        "summary": f"Condor scan: {target}",
        "sections": [
            {
                "activityTitle": f"Condor Scan Complete — {target}",
                "activitySubtitle": f"Platform: {platform} · {total} finding(s)",
                "facts": facts,
            }
        ],
    }
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(webhook_url, json=payload)
        r.raise_for_status()
