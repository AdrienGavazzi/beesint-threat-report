from __future__ import annotations

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.TransportError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return status == 429 or status >= 500
    return False


_feodo_retry = retry(
    reraise=True,
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=1, max=30),
    retry=retry_if_exception(_is_retryable),
)


def _map_feodo_item(item: dict) -> dict:
    return {
        "ip_address": item["ip_address"],
        "port": item.get("port"),
        "status": item["status"],
        "malware": item["malware"],
        "first_seen": item["first_seen"],
        "last_online": item.get("last_online"),
        "country": item.get("country"),
        "as_number": item.get("as_number"),
        "as_name": item.get("as_name"),
    }


@_feodo_retry
async def fetch_feodo_snapshot(client: httpx.AsyncClient, feed_url: str) -> list[dict]:
    response = await client.get(feed_url)
    response.raise_for_status()
    payload = response.json()
    return [_map_feodo_item(item) for item in payload]
