from __future__ import annotations

from datetime import datetime

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from beesint_threat_report.validate.schemas import BreachEntry


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.TransportError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return status == 429 or status >= 500
    return False


_hibp_retry = retry(
    reraise=True,
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=1, max=30),
    retry=retry_if_exception(_is_retryable),
)


def _map_breach_item(item: dict) -> dict:
    return {
        "name": item["Name"],
        "title": item.get("Title") or item["Name"],
        "domain": item.get("Domain") or "",
        "breach_date": item["BreachDate"],
        "added_date": item["AddedDate"],
        "pwn_count": item.get("PwnCount", 0),
        "data_classes": item.get("DataClasses") or [],
        "is_verified": bool(item.get("IsVerified", False)),
        "is_sensitive": bool(item.get("IsSensitive", False)),
        "description": item.get("Description") or "",
    }


@_hibp_retry
async def fetch_hibp_breaches(client: httpx.AsyncClient, breaches_url: str) -> list[dict]:
    """Pull complet du catalogue HIBP, PAS de filtre temporel ici — laisse le filtre à
    filter_new_breaches, même convention que fetch_kev_feed (le cache stocke le catalogue complet
    réutilisable). Ne PAS reprendre le `fetch_recent_breaches(limit=10)` de beesint-jobs, qui
    tronque AVANT filtrage — sous-compterait une semaine chargée (cf. CDC Phase P5)."""
    response = await client.get(breaches_url, headers={"User-Agent": "BeeSINT-ThreatReport/1.0"})
    response.raise_for_status()
    payload = response.json()
    return [_map_breach_item(item) for item in payload]


def filter_new_breaches(entries: list[BreachEntry], period_start: datetime, period_end: datetime) -> list[BreachEntry]:
    return [entry for entry in entries if period_start <= entry.added_date <= period_end]
