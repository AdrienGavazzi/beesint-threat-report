from __future__ import annotations

import bz2
import json

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.TransportError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return status == 429 or status >= 500
    return False


_phishtank_retry = retry(
    reraise=True,
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=1, max=30),
    retry=retry_if_exception(_is_retryable),
)


def _map_phishtank_item(item: dict) -> dict:
    return {
        "phish_id": str(item["phish_id"]),
        "url": item["url"],
        "submission_time": item["submission_time"],
        "verified": item.get("verified") == "yes",
        "online": item.get("online") == "yes",
        "target": item.get("target") or "",
    }


@_phishtank_retry
async def fetch_phishtank_feed(
    client: httpx.AsyncClient, api_key: str, base_url: str = "http://data.phishtank.com/data"
) -> list[dict]:
    """Flux bulk "online-valid" — vérifié contre phishtank.com/developer_info.php : le format
    réel est compressé (.json.bz2), pas du JSON brut malgré le nom de fichier. Décompression
    stdlib (bz2), pas de dépendance ajoutée."""
    url = f"{base_url}/{api_key}/online-valid.json.bz2"
    response = await client.get(url)
    response.raise_for_status()
    payload = json.loads(bz2.decompress(response.content))
    return [_map_phishtank_item(item) for item in payload]
