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


_SPARKLINE_COLOR = "#38BDF8"  # --color-primary-light — visible sur fond sombre à petite taille
_DEGRADED_STATUS_PREFIXES = ("failed",)


def _fmt_date(value: datetime) -> str:
    return value.strftime("%d %B %Y")


def _build_sparkline_svg(
    values: list[float], width: int = 64, height: int = 20, color: str = _SPARKLINE_COLOR
) -> str | None:
    """SVG polyline pur Python (pas de lib de chart) — None si pas assez de points pour être
    lisible, jamais d'exception sur une série vide/plate (cf. philosophie "continue en dégradé")."""
    if len(values) < 2:
        return None
    lo, hi = min(values), max(values)
    span = (hi - lo) or 1  # série plate (toutes valeurs égales) — évite une division par zéro
    step = width / (len(values) - 1)
    points = " ".join(f"{i * step:.1f},{height - ((v - lo) / span * height):.1f}" for i, v in enumerate(values))
    return (
        f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" class="sparkline">'
        f'<polyline points="{points}" fill="none" stroke="{color}" stroke-width="1.5" '
        f'stroke-linecap="round" stroke-linejoin="round"/></svg>'
    )


def _build_executive_summary(kpis: ReportKpis, is_cold_start: bool, sources_status: dict[str, str]) -> str:
    """Synthèse en 2-4 phrases, langage simple — public cible : recruteur non-expert cyber
    (CDC §1). Jamais de comparaison "vs semaine dernière" sur un cold start (CDC §6)."""

    def trend_phrase(pct: float | None) -> str:
        if is_cold_start or pct is None:
            return ""
        if pct > 0:
            return f", up {pct:.0f}% from last week"
        if pct < 0:
            return f", down {abs(pct):.0f}% from last week"
        return ", unchanged from last week"

    sentences = [
        f"This week, the pipeline tracked {kpis.cve_critical_count} new critical CVEs"
        f"{trend_phrase(kpis.cve_critical_trend_pct)}."
    ]

    kev_sentence = f"{kpis.kev_new_count} were added to CISA's Known Exploited Vulnerabilities catalog"
    if kpis.kev_urgent_count > 0:
        kev_sentence += f", {kpis.kev_urgent_count} of them due for patching within 7 days"
    if kpis.kev_ransomware_count > 0:
        kev_sentence += ", including at least one tied to known ransomware activity"
    sentences.append(kev_sentence + ".")

    c2_noun = "server" if kpis.c2_active_count == 1 else "servers"
    c2_verb = "remains" if kpis.c2_active_count == 1 else "remain"
    sentences.append(
        f"{kpis.c2_active_count} command-and-control {c2_noun} {c2_verb} active and "
        f"{kpis.malicious_url_count} malicious URLs were seen online in the monitored feeds."
    )

    degraded = [name for name, status in sources_status.items() if status.startswith(_DEGRADED_STATUS_PREFIXES)]
    if degraded:
        sentences.append(
            f"Note: {', '.join(sorted(degraded))} did not respond normally this run — "
            "the pipeline continued with the remaining sources rather than failing outright."
        )

    return " ".join(sentences)


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
    sources_status: dict[str, str],
    is_cold_start: bool,
    history_entries: list[dict],
) -> dict:
    period_start_str = _fmt_date(period_start)
    period_end_str = _fmt_date(period_end)
    generated_at_str = _fmt_date(generated_at)

    def _series(key: str, current: int) -> list[float]:
        return [h[key] for h in history_entries if key in h] + [current]

    threatfox_enabled = sources_status.get("threatfox") == "ok"

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
        "executive_summary": _build_executive_summary(kpis, is_cold_start, sources_status),
        "sources_status": [{"name": name, "status": status} for name, status in sorted(sources_status.items())],
        "cve": {
            "critical_count": kpis.cve_critical_count,
            "critical_trend_pct": kpis.cve_critical_trend_pct,
            "high_volume_count": kpis.cve_high_count,
            "critical_items": critical_items,
            "sparkline": _build_sparkline_svg(_series("cve_critical_count", kpis.cve_critical_count)),
        },
        "kev": {
            "new_count": kpis.kev_new_count,
            "trend_pct": kpis.kev_new_trend_pct,
            "urgent_count": kpis.kev_urgent_count,
            "items": _kev_items(kev_df),
            "urgency_flag": kpis.kev_ransomware_count > 0,
            "sparkline": _build_sparkline_svg(_series("kev_new_count", kpis.kev_new_count)),
        },
        "mttk": {
            "average_days": kpis.mean_time_to_kev_days,
            "median_days": mttk_median_days,
            "sample_size": mttk_sample_size,
        },
        "c2": {
            "active_count": kpis.c2_active_count,
            "trend_pct": kpis.c2_active_trend_pct,
            "items": c2_items,
            "sparkline": _build_sparkline_svg(_series("c2_active_count", kpis.c2_active_count)),
        },
        "malicious_urls": {
            "online_count": kpis.malicious_url_count,
            "trend_pct": kpis.malicious_url_trend_pct,
            "items": malicious_url_items,
            "sparkline": _build_sparkline_svg(_series("malicious_url_count", kpis.malicious_url_count)),
        },
        "threatfox": {
            "enabled": threatfox_enabled,
            "families_count": kpis.threatfox_malware_families_count,
            "families_trend_pct": kpis.threatfox_malware_families_trend_pct,
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
