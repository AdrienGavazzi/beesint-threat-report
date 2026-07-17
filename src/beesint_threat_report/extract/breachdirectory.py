from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)

_HOST = "breachdirectory.p.rapidapi.com"
_URL = f"https://{_HOST}/"


async def check_breachdirectory(client: httpx.AsyncClient, term: str, api_key: str) -> int:
    """Cross-check secondaire BreachDirectory (RapidAPI) sur la breach la plus impactante du run
    (spotlight) — port async fin du client de beesint-jobs/src/beesint_jobs/sources/
    breachdirectory.py. Logique dupliquée volontairement (pas d'import cross-repo, les 2 repos
    sont indépendants). Ne bloque jamais le pipeline : retourne 0 sur n'importe quelle erreur ;
    l'appelant (orchestrate.py) ne fait cet appel que si settings.rapidapi_key est présent."""
    try:
        headers = {"x-rapidapi-host": _HOST, "x-rapidapi-key": api_key}
        response = await client.get(_URL, params={"func": "auto", "term": term}, headers=headers)
        if response.status_code == 404:
            return 0
        response.raise_for_status()
        data = response.json()
        if not data.get("success"):
            return 0
        found = data.get("found")
        if isinstance(found, int):
            return found
        result = data.get("result")
        if isinstance(result, list):
            return len(result)
        return 0
    except Exception as exc:
        logger.warning("breachdirectory: échec du check pour %r (%s)", term, exc)
        return 0
