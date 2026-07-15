from __future__ import annotations

import asyncio
import logging

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)

_CONCURRENCY = 5


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.TransportError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return status == 429 or status >= 500
    return False


_shodan_retry = retry(
    reraise=True,
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=15),
    retry=retry_if_exception(_is_retryable),
)


@_shodan_retry
async def _fetch_one(client: httpx.AsyncClient, ip: str, base_url: str) -> dict | None:
    response = await client.get(f"{base_url}/{ip}")
    if response.status_code == 404:
        return None  # IP non indexée par Shodan — "pas de données", pas une erreur
    response.raise_for_status()
    payload = response.json()
    return {
        "ip": ip,
        "ports": payload.get("ports", []),
        "vulns": payload.get("vulns", []),
        "tags": payload.get("tags", []),
    }


async def fetch_internetdb_for_ips(
    client: httpx.AsyncClient,
    ips: list[str],
    base_url: str = "https://internetdb.shodan.io",
    concurrency: int = _CONCURRENCY,
) -> list[dict]:
    """Un appel HTTP par IP (pas de endpoint batch sur le tier gratuit InternetDB) — semaphore
    pour borner la concurrence, même philosophie que geoloc.py (rate-limit ip-api.com). N'est
    censé être appelé que sur la liste déjà réduite post rank_top_n_ips (orchestrate.py), jamais
    sur le feed FeodoTracker complet non trié."""
    semaphore = asyncio.Semaphore(concurrency)

    async def _bounded(ip: str) -> dict | None:
        async with semaphore:
            try:
                return await _fetch_one(client, ip, base_url)
            except (httpx.TransportError, httpx.HTTPStatusError) as exc:
                logger.warning("shodan_internetdb: échec pour %s (%s), IP ignorée", ip, exc)
                return None

    results = await asyncio.gather(*(_bounded(ip) for ip in ips))
    return [r for r in results if r is not None]
