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
    return df.sort(
        by=["is_new", "date_added", "url"],
        descending=[True, True, False],
    ).head(n)
