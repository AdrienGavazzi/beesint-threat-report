from __future__ import annotations

from datetime import datetime

import polars as pl

from beesint_threat_report.load.countries import country_name
from beesint_threat_report.load.cwe_names import cwe_name
from beesint_threat_report.transform.kpis import ReportKpis

_TOP_N_COUNTRIES = 10
_URL_TRUNCATE_LEN = 80

_SOURCES = [
    {
        "name": "NVD (National Vulnerability Database)",
        "url": "https://nvd.nist.gov/",
        "note": "Domaine public — NIST.",
    },
    {
        "name": "CISA Known Exploited Vulnerabilities (KEV)",
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "note": "Domaine public — CISA.",
    },
    {
        "name": "abuse.ch FeodoTracker",
        "url": "https://feodotracker.abuse.ch/",
        "note": "Data kindly provided by abuse.ch",
    },
    {
        "name": "abuse.ch URLhaus",
        "url": "https://urlhaus.abuse.ch/",
        "note": "Data kindly provided by abuse.ch",
    },
    {
        "name": "abuse.ch ThreatFox",
        "url": "https://threatfox.abuse.ch/",
        "note": "Data kindly provided by abuse.ch",
    },
    {
        "name": "ip-api.com",
        "url": "https://ip-api.com/",
        "note": "Géolocalisation IP, usage non-commercial.",
    },
]


def _fmt_date(value: datetime) -> str:
    return value.strftime("%d %B %Y")


def _geo_top_countries(feodo_df: pl.DataFrame, n: int) -> list[dict]:
    if feodo_df.height == 0 or "country" not in feodo_df.columns:
        return []
    counted = (
        feodo_df.filter(pl.col("country").is_not_null())
        .group_by("country")
        .agg(pl.len().alias("count"))
        .sort("count", descending=True)
    )
    total = counted["count"].sum()
    if not total:
        return []
    rows = counted.head(n).to_dicts()
    return [
        {
            "country_name": country_name(row["country"]),
            "country_code": row["country"],
            "count": row["count"],
            "pct_of_total": round(row["count"] / total * 100, 1),
        }
        for row in rows
    ]


def _cwe_top_items(cwe_distribution: list[dict], n: int) -> list[dict]:
    total = sum(row["count"] for row in cwe_distribution)
    if not total:
        return []
    return [
        {
            "cwe_id": row["cwe_id"],
            "cwe_name": cwe_name(row["cwe_id"]),
            "count": row["count"],
            "pct_of_total": round(row["count"] / total * 100, 1),
        }
        for row in cwe_distribution[:n]
    ]


def _kev_items(kev_df: pl.DataFrame) -> list[dict]:
    if kev_df.height == 0:
        return []
    items = []
    for row in kev_df.to_dicts():
        date_added = row.get("date_added")
        items.append(
            {
                "cve_id": row["cve_id"],
                "vendor_project": row.get("vendor_project"),
                "product": row.get("product"),
                "date_added": date_added.isoformat() if hasattr(date_added, "isoformat") else date_added,
                "ransomware_known_use": row.get("known_ransomware_campaign_use") == "Known",
            }
        )
    return items


def build_c2_items(top_ips: list[dict]) -> list[dict]:
    return [
        {
            "ip_address": item["ip"],
            "country": item.get("country"),
            "asn": item.get("asn"),
            "malware_family": item.get("malware"),
            "first_seen": item.get("first_seen"),
            "last_online": item.get("last_seen"),
        }
        for item in top_ips
    ]


def build_malicious_url_items(ranked_urlhaus_df: pl.DataFrame) -> list[dict]:
    if ranked_urlhaus_df.height == 0:
        return []
    items = []
    for row in ranked_urlhaus_df.to_dicts():
        url = row["url"]
        if len(url) > _URL_TRUNCATE_LEN:
            # "..." ASCII plutôt que le glyphe unicode "…" : absent des webfonts embarqués
            # (Syne/PJS/JetBrains Mono, subsets Latin), provoquerait un fallback système
            # (police interdite, cf. lot 5 "aucune police système de fallback").
            url = url[: _URL_TRUNCATE_LEN - 3] + "..."
        date_added = row.get("date_added")
        items.append(
            {
                "url": url,
                "threat_type": row.get("threat"),
                "tags": row.get("tags") or [],
                "date_added": date_added.isoformat() if hasattr(date_added, "isoformat") else date_added,
            }
        )
    return items


def build_pdf_context(
    *,
    run_id: str,
    period_start: datetime,
    period_end: datetime,
    generated_at: datetime,
    kpis: ReportKpis,
    critical_items: list[dict],
    kev_df: pl.DataFrame,
    mttk_median_days: float | None,
    mttk_sample_size: int,
    feodo_df: pl.DataFrame,
    c2_items: list[dict],
    malicious_url_items: list[dict],
    pipeline_duration_seconds: float,
) -> dict:
    period_start_str = _fmt_date(period_start)
    period_end_str = _fmt_date(period_end)
    generated_at_str = _fmt_date(generated_at)

    return {
        "report": {
            "run_id": run_id,
            "period_start": period_start_str,
            "period_end": period_end_str,
            "generated_at": generated_at_str,
            "kpi_summary": {
                "cve_critical_count": kpis.cve_critical_count,
                "kev_new_count": kpis.kev_new_count,
                "c2_active_count": kpis.c2_active_count,
                "malicious_url_count": kpis.malicious_url_count,
            },
        },
        "cve": {
            "critical_count": kpis.cve_critical_count,
            "critical_trend_pct": kpis.cve_critical_trend_pct,
            "high_volume_count": kpis.cve_high_count,
            "critical_items": critical_items,
        },
        "kev": {
            "new_count": kpis.kev_new_count,
            "items": _kev_items(kev_df),
            "urgency_flag": kpis.kev_ransomware_count > 0,
        },
        "mttk": {
            "average_days": kpis.mean_time_to_kev_days,
            "median_days": mttk_median_days,
            "sample_size": mttk_sample_size,
        },
        "c2": {
            "active_count": kpis.c2_active_count,
            "items": c2_items,
        },
        "malicious_urls": {
            "online_count": kpis.malicious_url_count,
            "items": malicious_url_items,
        },
        "geo": {
            "top_countries": _geo_top_countries(feodo_df, _TOP_N_COUNTRIES),
        },
        "vendors": {
            "top_items": [{"vendor_name": row["vendor"], "cve_count": row["count"]} for row in kpis.top_vendors],
        },
        "cwe": {
            "top_items": _cwe_top_items(kpis.cwe_distribution, _TOP_N_COUNTRIES),
        },
        "lineage": {
            "run_id": run_id,
            "period_start": period_start_str,
            "period_end": period_end_str,
            "generated_at": generated_at_str,
            "sources": _SOURCES,
            "pipeline_duration_seconds": round(pipeline_duration_seconds, 2),
        },
    }
