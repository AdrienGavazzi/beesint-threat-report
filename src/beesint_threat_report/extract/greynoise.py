from __future__ import annotations

import asyncio
import logging

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)

_CONCURRENCY = 2  # tier gratuit très limité en rate — concurrence basse, cf. geoloc.py (ip-api.com)


class GreyNoiseRateLimitedError(Exception):
    """429 reçu — jamais retryable ici (cf. _is_retryable), déclenche l'arrêt des appels
    restants côté fetch_greynoise_classifications plutôt qu'un retry-loop (CDC "continue en
    dégradé" : un rate-limit mi-run n'est pas une erreur fatale)."""


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.TransportError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code >= 500  # jamais 429 ici, cf. GreyNoiseRateLimitedError
    return False


_greynoise_retry = retry(
    reraise=True,
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=15),
    retry=retry_if_exception(_is_retryable),
)


@_greynoise_retry
async def _fetch_one(client: httpx.AsyncClient, ip: str, api_key: str, base_url: str) -> dict | None:
    response = await client.get(f"{base_url}/{ip}", headers={"key": api_key})
    if response.status_code == 429:
        raise GreyNoiseRateLimitedError(f"greynoise: 429 sur {ip}")
    if response.status_code == 404:
        return None  # IP jamais observée par GreyNoise
    response.raise_for_status()
    payload = response.json()
    classification = payload.get("classification")
    if not classification:
        return None
    # Valeur brute conservée telle quelle (pas de remap "benign"->"scanner") : vérifié contre
    # docs.greynoise.io/docs/using-the-greynoise-community-api — "benign" désigne spécifiquement
    # une IP du dataset RIOT (infra "Business Services" connue et de confiance, ex. Cloudflare
    # 1.1.1.1), pas "un scanner internet connu". Le champ dédié aux scanners est `noise` (booléen,
    # non exposé ici), distinct de `classification`. Remapper "benign"->"scanner" aurait donc été
    # une mistraduction du sens réel du champ (cf. CDC : "keep GreyNoise's own field values as-is
    # rather than potentially mistranslating them").
    return {"ip": ip, "classification": classification}


async def fetch_greynoise_classifications(
    client: httpx.AsyncClient,
    ips: list[str],
    api_key: str,
    base_url: str = "https://api.greynoise.io/v3/community",
    concurrency: int = _CONCURRENCY,
) -> list[dict]:
    """Un appel HTTP par IP (tier community, pas de batch) — s'arrête au premier 429 plutôt que
    de retenter en boucle : les IP restantes repartent simplement sans classification GreyNoise
    ce run, jamais un run entier en échec pour un rate-limit tiers."""
    results: list[dict] = []
    rate_limited = False
    semaphore = asyncio.Semaphore(concurrency)

    async def _bounded(ip: str) -> None:
        nonlocal rate_limited
        if rate_limited:
            return
        async with semaphore:
            if rate_limited:
                return
            try:
                data = await _fetch_one(client, ip, api_key, base_url)
                if data:
                    results.append(data)
            except GreyNoiseRateLimitedError:
                logger.warning("greynoise: 429 reçu, IP restantes ignorées ce run")
                rate_limited = True
            except (httpx.TransportError, httpx.HTTPStatusError) as exc:
                logger.warning("greynoise: échec pour %s (%s), IP ignorée", ip, exc)

    await asyncio.gather(*(_bounded(ip) for ip in ips))
    return results
