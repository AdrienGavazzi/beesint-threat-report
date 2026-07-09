from __future__ import annotations

import asyncio
import logging

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from beesint_threat_report.validate.schemas import FeodoIpRecord

logger = logging.getLogger(__name__)

_BATCH_SIZE = 100
_RATE_LIMIT_PER_MINUTE = 45


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.TransportError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return status == 429 or status >= 500
    return False


@retry(
    reraise=True,
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=1, max=30),
    retry=retry_if_exception(_is_retryable),
)
async def _fetch_batch(client: httpx.AsyncClient, batch_url: str, ips: list[str]) -> list[dict]:
    response = await client.post(batch_url, json=ips)
    response.raise_for_status()
    return response.json()


async def enrich_ips_geoloc(
    client: httpx.AsyncClient, ip_records: list[FeodoIpRecord], batch_url: str
) -> dict[str, dict]:
    results: dict[str, dict] = {}
    batches = [ip_records[i : i + _BATCH_SIZE] for i in range(0, len(ip_records), _BATCH_SIZE)]

    for idx, batch in enumerate(batches):
        ips = [record.ip_address for record in batch]
        try:
            data = await _fetch_batch(client, batch_url, ips)
        except (httpx.TransportError, httpx.HTTPStatusError) as exc:
            logger.warning("geoloc: lot %s omis après échec définitif (%s)", idx, exc)
            continue

        for entry in data:
            if entry.get("status") != "success":
                continue
            ip = entry.get("query")
            results[ip] = {
                "lat": entry.get("lat"),
                "lon": entry.get("lon"),
                "country": entry.get("country"),
                "city": entry.get("city"),
                "isp": entry.get("isp"),
                "asn": entry.get("as"),
            }

        if idx < len(batches) - 1:
            await asyncio.sleep(60 / _RATE_LIMIT_PER_MINUTE)

    return results
