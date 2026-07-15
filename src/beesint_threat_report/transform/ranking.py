from __future__ import annotations

import polars as pl


def rank_top_n_cves(df: pl.DataFrame, n: int) -> pl.DataFrame:
    return df.sort(
        by=["cvss_v3_score", "published_date", "cve_id"],
        descending=[True, True, False],
    ).head(n)


def rank_top_n_ips(df: pl.DataFrame, n: int) -> pl.DataFrame:
    return df.sort(
        by=["is_new", "first_seen", "ip_address"],
        descending=[True, True, False],
    ).head(n)


def rank_top_n_urls(df: pl.DataFrame, n: int) -> pl.DataFrame:
    """Si une colonne "sources" (merge PhishTank, cf. transform/phishtank_merge.py) est présente,
    le nombre de sources confirmant l'URL prime sur les critères historiques — une entrée
    confirmée par 2 feeds passe devant une entrée à 1 seule source, cf. CDC "Data source
    integration rule". Rétro-compatible avec un df sans "sources" (tri inchangé)."""
    if "sources" in df.columns:
        df = df.with_columns(pl.col("sources").list.len().alias("_sources_count"))
        result = df.sort(
            by=["_sources_count", "is_new", "date_added", "url"],
            descending=[True, True, True, False],
        ).head(n)
        return result.drop("_sources_count")
    return df.sort(
        by=["is_new", "date_added", "url"],
        descending=[True, True, False],
    ).head(n)
