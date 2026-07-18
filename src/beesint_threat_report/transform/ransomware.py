from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from beesint_threat_report.extract.ransomware_live import normalize_group_name

if TYPE_CHECKING:
    from beesint_threat_report.validate.schemas import RansomwareGroup, RansomwarePost


def _week_bucket_index(discovered: datetime, period_end: datetime, weeks: int) -> int | None:
    """Bucket 0 = plus ancien, `weeks - 1` = semaine la plus récente (celle qui contient
    period_end) — même ordre chronologique attendu par _build_sparkline_svg (série
    ancien -> récent)."""
    delta_days = (period_end - discovered).days
    if delta_days < 0:
        return None
    idx = weeks - 1 - (delta_days // 7)
    if idx < 0 or idx >= weeks:
        return None
    return idx


def build_group_aggregates(
    posts_this_week: list[RansomwarePost],
    posts_last_n_weeks: list[RansomwarePost],
    groups_by_normalized_name: dict[str, RansomwareGroup],
    period_end: datetime,
    weeks: int = 6,
) -> list[dict]:
    """Un groupe = un dict {name, count, victim_count_lifetime, is_raas, sparkline_weekly_counts,
    profile_url} — jamais une liste de victimes (cf. décision produit éthique). Trié par count
    décroissant, même convention que rank_top_n_*."""
    counts_by_group: dict[str, int] = {}
    display_name_by_group: dict[str, str] = {}
    for post in posts_this_week:
        key = normalize_group_name(post.group_name)
        counts_by_group[key] = counts_by_group.get(key, 0) + 1
        display_name_by_group.setdefault(key, post.group_name)

    result = []
    for key, count in sorted(counts_by_group.items(), key=lambda kv: kv[1], reverse=True):
        buckets = [0] * weeks
        for post in posts_last_n_weeks:
            if normalize_group_name(post.group_name) != key:
                continue
            idx = _week_bucket_index(post.discovered, period_end, weeks)
            if idx is not None:
                buckets[idx] += 1

        group = groups_by_normalized_name.get(key)
        result.append(
            {
                "name": display_name_by_group[key],
                "count": count,
                "victim_count_lifetime": group.victim_count_lifetime if group else 0,
                "is_raas": bool(group.is_raas) if group else False,
                "sparkline_weekly_counts": buckets,
                "profile_url": f"https://www.ransomware.live/group/{key}",
            }
        )
    return result


def build_sector_breakdown(posts_this_week: list[RansomwarePost], n: int = 10) -> list[dict]:
    """Même forme 3-champs que MalwareFamilyBreakdownItem/AsnBreakdownItem côté frontend
    (name/count/pct_of_total) — group by activity (secteur), pas de chip-list ici (rendu confié
    au lollipop chart côté pdf_context.py, cf. décision UX "pas un 6e chip-list")."""
    if not posts_this_week:
        return []
    counted: dict[str, int] = {}
    for post in posts_this_week:
        counted[post.activity] = counted.get(post.activity, 0) + 1
    total = sum(counted.values())
    rows = sorted(counted.items(), key=lambda kv: kv[1], reverse=True)[:n]
    return [{"sector": sector, "count": count, "pct_of_total": round(count / total * 100, 1)} for sector, count in rows]
