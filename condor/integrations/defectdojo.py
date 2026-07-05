"""DefectDojo export adapter for Condor scan results."""
from __future__ import annotations

import datetime

import httpx

from ..core.models import ScanResult

_SEVERITY_MAP = {
    "critical": "Critical",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Low",
    "info":     "Info",
}


async def export_to_defectdojo(
    result: ScanResult,
    url: str,
    api_key: str,
    product_name: str,
    engagement_name: str = "Condor Scan",
) -> None:
    base = url.rstrip("/")
    headers = {"Authorization": f"Token {api_key}", "Content-Type": "application/json"}

    async with httpx.AsyncClient(timeout=30, headers=headers) as client:
        # 1. Get or create product
        r = await client.get(f"{base}/api/v2/products/", params={"name": product_name})
        r.raise_for_status()
        data = r.json()
        products = data.get("results", [])
        if products:
            product_id = products[0]["id"]
        else:
            r = await client.post(
                f"{base}/api/v2/products/",
                json={"name": product_name, "description": product_name, "prod_type": 1},
            )
            r.raise_for_status()
            product_id = r.json()["id"]

        # 2. Create engagement
        now = datetime.date.today().isoformat()
        r = await client.post(
            f"{base}/api/v2/engagements/",
            json={
                "name": engagement_name,
                "product": product_id,
                "target_start": now,
                "target_end": now,
                "engagement_type": "CI/CD",
                "status": "Completed",
            },
        )
        r.raise_for_status()
        engagement_id = r.json()["id"]

        # 3. Create test (required FK for findings)
        r = await client.post(
            f"{base}/api/v2/tests/",
            json={
                "engagement": engagement_id,
                "test_type": 1,
                "target_start": now,
                "target_end": now,
                "environment": 1,
            },
        )
        r.raise_for_status()
        test_id = r.json()["id"]

        # 4. Create findings
        for f in result.findings:
            description = f.description
            if f.evidence:
                description += f"\n\nEvidence:\n{f.evidence}"

            payload: dict = {
                "test": test_id,
                "title": f.title,
                "description": description,
                "severity": _SEVERITY_MAP.get(f.severity.value, "Info"),
                "verified": False,
                "active": True,
                "tags": [f.owasp_id.value],
            }
            if f.cwe_id:
                try:
                    payload["cwe"] = int(f.cwe_id.split("-")[1])
                except (ValueError, IndexError):
                    pass
            if f.endpoint:
                payload["url"] = f.endpoint

            r = await client.post(f"{base}/api/v2/findings/", json=payload)
            r.raise_for_status()
