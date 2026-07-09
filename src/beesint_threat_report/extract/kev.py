from __future__ import annotations

from datetime import datetime

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from beesint_threat_report.validate.schemas import KevEntry


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.TransportError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return status == 429 or status >= 500
    return False


_kev_retry = retry(
    reraise=True,
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=1, max=30),
    retry=retry_if_exception(_is_retryable),
)


def _map_kev_item(item: dict) -> dict:
    return {
        "cve_id": item["cveID"],
        "vendor_project": item["vendorProject"],
        "product": item["product"],
        "vulnerability_name": item["vulnerabilityName"],
        "date_added": item["dateAdded"],
        "short_description": item["shortDescription"],
        "required_action": item["requiredAction"],
        "due_date": item["dueDate"],
        "known_ransomware_campaign_use": item["knownRansomwareCampaignUse"],
    }


@_kev_retry
async def fetch_kev_feed(client: httpx.AsyncClient, feed_url: str) -> list[dict]:
    """Pull complet du feed KEV, PAS de filtre temporel ici — laisse le filtre à
    filter_new_entries pour que le cache stocke le feed complet réutilisable."""
    response = await client.get(feed_url)
    response.raise_for_status()
    payload = response.json()
    return [_map_kev_item(item) for item in payload.get("vulnerabilities", [])]


def filter_new_entries(entries: list[KevEntry], period_start: datetime, period_end: datetime) -> list[KevEntry]:
    return [entry for entry in entries if period_start <= entry.date_added <= period_end]
