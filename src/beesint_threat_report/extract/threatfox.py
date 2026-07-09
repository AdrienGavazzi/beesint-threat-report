from __future__ import annotations

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential


class ThreatFoxAuthError(Exception):
    """Auth-Key absente/invalide (HTTP 401/403) — jamais retryable, cf. lot 7."""


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.TransportError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return status == 429 or status >= 500
    return False


_threatfox_retry = retry(
    reraise=True,
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=1, max=30),
    retry=retry_if_exception(_is_retryable),
)


def _strip_utc_suffix(value):
    # même format non-ISO8601 "YYYY-MM-DD HH:MM:SS UTC" que urlhaus.py (cf. commentaire
    # _map_urlhaus_item) — vérifié cohérent entre feeds abuse.ch.
    if isinstance(value, str) and value.endswith(" UTC"):
        return value[: -len(" UTC")]
    return value


def _map_threatfox_item(item: dict) -> dict:
    return {
        "ioc_id": str(item["id"]),
        "ioc_type": item["ioc_type"],
        "ioc_value": item["ioc"],
        "threat_type": item.get("threat_type", ""),
        "malware": item.get("malware", ""),
        "malware_printable": item.get("malware_printable", ""),
        "confidence_level": item.get("confidence_level", 0),
        "first_seen": _strip_utc_suffix(item.get("first_seen_utc")),
        "last_seen": _strip_utc_suffix(item.get("last_seen_utc")),
        "reporter": item.get("reporter", ""),
        "tags": item.get("tags") or [],
    }


@_threatfox_retry
async def fetch_threatfox(
    client: httpx.AsyncClient,
    auth_key: str,
    days: int = 7,
    base_url: str = "https://threatfox-api.abuse.ch/api/v1/",
) -> list[dict]:
    """POST get_iocs avec Auth-Key. 401/403 -> ThreatFoxAuthError, non-retryable (un seul
    appel HTTP). "no_result" traité comme liste vide, tout autre statut hors "ok" = erreur."""
    try:
        response = await client.post(base_url, json={"query": "get_iocs", "days": days}, headers={"Auth-Key": auth_key})
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code in (401, 403):
            raise ThreatFoxAuthError(f"ThreatFox Auth-Key invalide (HTTP {exc.response.status_code})") from exc
        raise

    payload = response.json()
    query_status = payload.get("query_status")
    if query_status == "no_result":
        return []
    if query_status != "ok":
        raise ValueError(f"threatfox: query_status inattendu: {query_status!r}")
    return [_map_threatfox_item(item) for item in payload.get("data", [])]
