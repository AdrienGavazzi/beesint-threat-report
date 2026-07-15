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


_openphish_retry = retry(
    reraise=True,
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=1, max=30),
    retry=retry_if_exception(_is_retryable),
)


@_openphish_retry
async def fetch_openphish_feed(client: httpx.AsyncClient, feed_url: str) -> list[dict]:
    """Flux public communautaire — texte brut, une URL par ligne, aucune clé API requise (à la
    différence de PhishTank, dont les inscriptions sont désormais fermées). Même endpoint déjà
    utilisé ailleurs dans ce workspace (beesint-backend/modules/threat_intel.py)."""
    response = await client.get(feed_url)
    response.raise_for_status()
    return [{"url": line.strip()} for line in response.text.splitlines() if line.strip()]
