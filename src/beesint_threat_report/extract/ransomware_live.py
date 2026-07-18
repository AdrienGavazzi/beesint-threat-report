from __future__ import annotations

from datetime import datetime, timedelta

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.TransportError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return status == 429 or status >= 500
    return False


_ransomware_live_retry = retry(
    reraise=True,
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=1, max=30),
    retry=retry_if_exception(_is_retryable),
)


def normalize_group_name(name: str) -> str:
    """posts.json::group_name et groups.json::name ne partagent pas toujours la même casse/
    espacement (confirmé : 4 groupes actifs sur 32 lors d'un test réel ne matchaient pas par
    égalité stricte) — toute jointure entre les deux dumps doit passer par cette normalisation,
    jamais une comparaison brute."""
    return name.strip().lower()


def _map_post_item(item: dict) -> dict:
    # post_title/website/post_url DÉLIBÉRÉMENT absents — même garantie qu'au niveau du modèle
    # RansomwarePost (validate/schemas.py), doublée ici : ces champs ne doivent jamais transiter,
    # même en amont de la validation Pydantic.
    # "Not Found" est le placeholder littéral de la source pour un secteur non catégorisé
    # (confirmé sur données réelles) — normalisé en "Unknown" ici, même endroit que le reste du
    # nettoyage de champ, pas éparpillé dans la couche transform.
    activity = item.get("activity") or "Unknown"
    if activity == "Not Found":
        activity = "Unknown"
    return {
        "group_name": item["group_name"],
        "activity": activity,
        "country": item.get("country"),
        "discovered": item["discovered"],
        "published": item.get("published"),
    }


def _map_group_item(item: dict) -> dict:
    # `locations` (métadonnées de scraping .onion) délibérément ignoré ici — jamais mappé, jamais
    # conservé en mémoire au-delà de ce point.
    return {
        "name": item["name"],
        "altname": item.get("altname"),
        "lineage": item.get("lineage"),
        "description": item.get("description"),
        "is_raas": bool((item.get("type") or {}).get("raas")),
        "victim_count_lifetime": item.get("_victim_count") or 0,
    }


@_ransomware_live_retry
async def fetch_ransomware_posts(client: httpx.AsyncClient, posts_url: str) -> list[dict]:
    """Dump JSON complet (~20 Mo, historique entier depuis l'origine du projet) — aucun filtre
    de date côté serveur, tout le filtrage se fait côté extracteur (filter_posts_by_window/
    filter_posts_last_n_weeks), sur les dicts bruts, AVANT validate_batch (cf. orchestrate.py) :
    valider les ~30 000 lignes avec Pydantic pour n'en garder que ~160 serait un gâchis qui
    empirera avec la croissance du dump."""
    response = await client.get(posts_url)
    response.raise_for_status()
    payload = response.json()
    return [_map_post_item(item) for item in payload]


@_ransomware_live_retry
async def fetch_ransomware_groups(client: httpx.AsyncClient, groups_url: str) -> list[dict]:
    response = await client.get(groups_url)
    response.raise_for_status()
    payload = response.json()
    return [_map_group_item(item) for item in payload]


def filter_posts_by_window(raw_posts: list[dict], period_start: datetime, period_end: datetime) -> list[dict]:
    """Filtre les dicts BRUTS (pas encore des RansomwarePost) sur `discovered` — volontairement
    avant validation, cf. docstring fetch_ransomware_posts. `period_start`/`period_end` doivent
    être timezone-aware (toujours le cas côté orchestrate.py, cf. CDC §12 "UTC unique")."""

    def _discovered(post: dict) -> datetime | None:
        raw = post.get("discovered")
        if not raw:
            return None
        try:
            return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except ValueError:
            return None

    result = []
    for post in raw_posts:
        discovered = _discovered(post)
        if discovered is not None and period_start <= discovered <= period_end:
            result.append(post)
    return result


def filter_posts_last_n_weeks(raw_posts: list[dict], period_end: datetime, weeks: int = 6) -> list[dict]:
    """Fenêtre plus large que filter_posts_by_window — alimente les sparklines par groupe
    (tendance sur plusieurs semaines), toujours sur les dicts bruts avant validation."""
    lo = period_end - timedelta(weeks=weeks)
    return filter_posts_by_window(raw_posts, lo, period_end)
