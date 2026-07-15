from __future__ import annotations

from datetime import datetime
from urllib.parse import urlparse, urlunparse

import polars as pl

from beesint_threat_report.validate.schemas import OpenPhishEntry


def _normalize_url(url: str) -> str:
    """Scheme + host en minuscule, slash de fin retiré sur le path — path/query/fragment
    inchangés (case-sensitive)."""
    parsed = urlparse(url.strip())
    path = parsed.path.rstrip("/")
    return urlunparse(parsed._replace(scheme=parsed.scheme.lower(), netloc=parsed.netloc.lower(), path=path))


def merge_openphish_urls(
    urlhaus_df: pl.DataFrame, openphish_entries: list[OpenPhishEntry], observed_at: datetime
) -> pl.DataFrame:
    """Fusionne OpenPhish dans urlhaus_df par URL normalisée (colonne "sources" étendue, jamais
    de doublon) — même pattern que transform/threatfox.py::merge_threatfox_ip_iocs pour les IP
    (remplace l'ancien merge_phishtank_urls, PhishTank étant retiré). Une URL présente dans les
    deux flux devient UNE entrée avec sources=["urlhaus","openphish"] ; une URL OpenPhish-only
    devient une nouvelle ligne avec sources=["openphish"].
    `observed_at` (period_end du run) sert de date_added pour les nouvelles lignes : le flux
    OpenPhish ne fournit aucun horodatage par URL (contrairement à PhishTank submission_time),
    seule l'observation "vue dans ce run" est disponible.
    Doit tourner AVANT ranking.rank_top_n_urls (cf. CDC : le cut top-N doit voir sources_count)."""
    if urlhaus_df.height and "sources" not in urlhaus_df.columns:
        urlhaus_df = urlhaus_df.with_columns(pl.Series("sources", [["urlhaus"]] * urlhaus_df.height))

    if not openphish_entries:
        return urlhaus_df

    normalized_urlhaus: dict[str, int] = {}
    if urlhaus_df.height:
        for idx, url in enumerate(urlhaus_df["url"].to_list()):
            normalized_urlhaus.setdefault(_normalize_url(url), idx)

    matched_indices: set[int] = set()
    new_rows: list[dict] = []
    seen_openphish_norm: set[str] = set()
    for entry in openphish_entries:
        norm = _normalize_url(entry.url)
        if norm in seen_openphish_norm:
            continue  # feed OpenPhish lui-même dédupliqué par URL normalisée, 1ère occurrence gagne
        seen_openphish_norm.add(norm)
        if norm in normalized_urlhaus:
            matched_indices.add(normalized_urlhaus[norm])
        else:
            new_rows.append(
                {
                    "url": entry.url,
                    "url_status": "online",
                    "date_added": observed_at,
                    # OpenPhish est un flux phishing exclusivement, comme PhishTank avant lui.
                    "threat": "phishing",
                    "tags": [],
                    "is_new": True,
                    "sources": ["openphish"],
                }
            )

    if matched_indices:
        sources_col = urlhaus_df["sources"].to_list()
        for idx in matched_indices:
            if "openphish" not in sources_col[idx]:
                sources_col[idx] = [*sources_col[idx], "openphish"]
        urlhaus_df = urlhaus_df.with_columns(pl.Series("sources", sources_col))

    if not new_rows:
        return urlhaus_df

    new_df = pl.DataFrame(new_rows)
    if urlhaus_df.height:
        # une colonne 100% null côté urlhaus_df s'infère en dtype Null, incompatible avec le
        # dtype réel de new_df pour pl.concat(how="vertical") — même recalage que
        # merge_threatfox_ip_iocs (transform/threatfox.py) pour ip_frame.
        null_cols = [c for c in urlhaus_df.columns if c in new_df.schema and urlhaus_df.schema[c] == pl.Null]
        if null_cols:
            urlhaus_df = urlhaus_df.with_columns([pl.col(c).cast(new_df.schema[c]) for c in null_cols])
        missing_in_new = [c for c in urlhaus_df.columns if c not in new_df.columns]
        for col in missing_in_new:
            new_df = new_df.with_columns(pl.lit(None, dtype=urlhaus_df.schema[col]).alias(col))
        mismatched = [c for c in new_df.columns if c in urlhaus_df.schema and new_df.schema[c] != urlhaus_df.schema[c]]
        if mismatched:
            new_df = new_df.with_columns([pl.col(c).cast(urlhaus_df.schema[c]) for c in mismatched])
        return pl.concat([urlhaus_df, new_df.select(urlhaus_df.columns)], how="vertical")
    return new_df
