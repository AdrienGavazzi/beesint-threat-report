from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import polars as pl

_URGENT_WINDOW_DAYS = 7
_TOP_N_AGGREGATES = 10


@dataclass(frozen=True)
class ReportKpis:
    cve_critical_count: int
    cve_critical_trend_pct: float | None  # vs run précédent, None si cold start
    cve_high_count: int
    kev_new_count: int
    kev_urgent_count: int  # subset avec dueDate <= J+7
    kev_ransomware_count: int  # knownRansomwareCampaignUse == "Known"
    mean_time_to_kev_days: float | None
    c2_active_count: int
    malicious_url_count: int
    top_countries: list[dict]  # [{country, count}], top 10
    top_vendors: list[dict]  # [{vendor, count}]
    cwe_distribution: list[dict]  # [{cwe_id, count}]


def _trend_pct(current: int, previous: int | None) -> float | None:
    if previous is None or previous == 0:
        return None
    return round((current - previous) / previous * 100, 2)


def _top_value_counts(df: pl.DataFrame, column: str, count_alias: str, n: int) -> list[dict]:
    if df.height == 0 or column not in df.columns:
        return []
    counted = (
        df.filter(pl.col(column).is_not_null())
        .group_by(column)
        .agg(pl.len().alias(count_alias))
        .sort(count_alias, descending=True)
        .head(n)
    )
    return counted.to_dicts()


def compute_kpis(
    cve_df: pl.DataFrame,
    kev_df: pl.DataFrame,
    feodo_df: pl.DataFrame,
    urlhaus_df: pl.DataFrame,
    mean_time_to_kev: float | None,
    previous_kpis: ReportKpis | None,
    cve_high_count: int = 0,
) -> ReportKpis:
    cve_critical_count = cve_df.height

    kev_new_count = kev_df.height
    if kev_df.height and "due_date" in kev_df.columns:
        urgent_cutoff = datetime.now(UTC) + timedelta(days=_URGENT_WINDOW_DAYS)
        kev_urgent_count = kev_df.filter(pl.col("due_date") <= urgent_cutoff).height
    else:
        kev_urgent_count = 0
    if kev_df.height and "known_ransomware_campaign_use" in kev_df.columns:
        kev_ransomware_count = kev_df.filter(pl.col("known_ransomware_campaign_use") == "Known").height
    else:
        kev_ransomware_count = 0

    c2_active_count = feodo_df.filter(pl.col("status") == "online").height if feodo_df.height else 0
    malicious_url_count = urlhaus_df.filter(pl.col("url_status") == "online").height if urlhaus_df.height else 0

    top_countries = [
        {"country": row["country"], "count": row["count"]}
        for row in _top_value_counts(feodo_df, "country", "count", _TOP_N_AGGREGATES)
    ]
    top_vendors = [
        {"vendor": row["vendor"], "count": row["count"]}
        for row in _top_value_counts(cve_df, "vendor", "count", _TOP_N_AGGREGATES)
    ]

    if cve_df.height and "cwe_ids" in cve_df.columns:
        cwe_counts = (
            cve_df.select(pl.col("cwe_ids").explode().alias("cwe_id"))
            .filter(pl.col("cwe_id").is_not_null())
            .group_by("cwe_id")
            .agg(pl.len().alias("count"))
            .sort("count", descending=True)
        )
        cwe_distribution = cwe_counts.to_dicts()
    else:
        cwe_distribution = []

    return ReportKpis(
        cve_critical_count=cve_critical_count,
        cve_critical_trend_pct=_trend_pct(
            cve_critical_count, previous_kpis.cve_critical_count if previous_kpis else None
        ),
        cve_high_count=cve_high_count,
        kev_new_count=kev_new_count,
        kev_urgent_count=kev_urgent_count,
        kev_ransomware_count=kev_ransomware_count,
        mean_time_to_kev_days=mean_time_to_kev,
        c2_active_count=c2_active_count,
        malicious_url_count=malicious_url_count,
        top_countries=top_countries,
        top_vendors=top_vendors,
        cwe_distribution=cwe_distribution,
    )
