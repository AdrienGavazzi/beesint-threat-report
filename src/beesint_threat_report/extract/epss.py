from __future__ import annotations

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

# limit posé explicitement à chaque appel : le défaut de l'API est 100, une semaine chargée en
# CVE critiques + KEV pourrait s'en approcher — ne jamais compter sur le défaut.
_EPSS_LIMIT = 200


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.TransportError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return status == 429 or status >= 500
    return False


_epss_retry = retry(
    reraise=True,
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=1, max=30),
    retry=retry_if_exception(_is_retryable),
)


def _map_epss_item(item: dict) -> dict:
    # epss/percentile arrivent en string décimale ("0.999990000") côté API — jamais un champ
    # str dans le modèle validé plus loin (EpssScore), parse ici avant que la donnée y entre.
    return {
        "cve_id": item["cve"],
        "epss_score": float(item["epss"]),
        "epss_percentile": float(item["percentile"]),
    }


@_epss_retry
async def fetch_epss_scores(client: httpx.AsyncClient, cve_ids: list[str], base_url: str) -> list[dict]:
    """Batch unique (comma-séparé), pas un appel par CVE. Un CVE inconnu de la base EPSS
    disparaît juste de `data` (jamais d'erreur, jamais de 404 par CVE) — dégradation déjà
    native côté API, rien à gérer côté extracteur au-delà de l'absence dans le résultat."""
    if not cve_ids:
        return []
    response = await client.get(base_url, params={"cve": ",".join(cve_ids), "limit": _EPSS_LIMIT})
    response.raise_for_status()
    payload = response.json()
    return [_map_epss_item(item) for item in payload.get("data", [])]
