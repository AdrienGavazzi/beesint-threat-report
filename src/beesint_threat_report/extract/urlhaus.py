from __future__ import annotations

from urllib.parse import urlparse

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.TransportError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return status == 429 or status >= 500
    return False


_urlhaus_retry = retry(
    reraise=True,
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=1, max=30),
    retry=retry_if_exception(_is_retryable),
)


def _map_urlhaus_item(item: dict) -> dict:
    # abuse.ch renvoie "YYYY-MM-DD HH:MM:SS UTC" — suffixe non-ISO8601 que Pydantic
    # rejette tel quel ; on le retire, _force_utc (validate/schemas.py) rattache le tz.
    date_added = item["dateadded"]
    if isinstance(date_added, str) and date_added.endswith(" UTC"):
        date_added = date_added[: -len(" UTC")]
    # l'API réelle ne renvoie pas de champ "host" — dérivé du netloc de l'URL elle-même
    # (vérifié empiriquement contre json_online, cf. CDC §5 recherche empirique).
    host = item.get("host") or urlparse(item["url"]).netloc
    return {
        "url": item["url"],
        "url_status": item["url_status"],
        "date_added": date_added,
        "threat": item["threat"],
        "tags": item.get("tags", []),
        "host": host,
        "reporter": item.get("reporter"),
    }


@_urlhaus_retry
async def fetch_urlhaus_online(client: httpx.AsyncClient, feed_url: str) -> list[dict]:
    """Pull le dump "online" (état courant) — jamais json_recent, cf. CDC §5."""
    response = await client.get(feed_url)
    response.raise_for_status()
    payload = response.json()
    # format abuse.ch: dict {id: [entry, ...]} — chaque id porte une liste d'une entrée
    return [_map_urlhaus_item(entry) for entries in payload.values() for entry in entries]
