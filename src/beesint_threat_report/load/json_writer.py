from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from beesint_threat_report.load.pdf_context import _TOP_N_COUNTRIES, _c2_cross_confirmed, _chip_breakdown
from beesint_threat_report.transform.kpis import ReportKpis

SCHEMA_VERSION = 1


def build_report_payload(
    run_id: str,
    period_start: str,
    period_end: str,
    status: str,
    kpis: ReportKpis,
    top_cves: list[dict],
    top_ips: list[dict],
    pipeline_duration_seconds: float,
    sources_status: dict[str, str],
    c2_items: list[dict],
    malicious_url_items: list[dict],
    malicious_url_pool_total: int = 0,
    is_cold_start: bool = False,
    ransomware_watch: dict | None = None,
) -> dict:
    return {
        "run_id": run_id,
        "period_start": period_start,
        "period_end": period_end,
        "status": status,
        "is_cold_start": is_cold_start,
        "sources_status": sources_status,
        "kpis": {
            "cve_critical_count": kpis.cve_critical_count,
            "cve_critical_trend_pct": kpis.cve_critical_trend_pct,
            "cve_high_count": kpis.cve_high_count,
            "kev_new_count": kpis.kev_new_count,
            "kev_new_trend_pct": kpis.kev_new_trend_pct,
            "kev_urgent_count": kpis.kev_urgent_count,
            "kev_ransomware_flag": kpis.kev_ransomware_count > 0,
            "mean_time_to_kev_days": kpis.mean_time_to_kev_days,
            "c2_active_count": kpis.c2_active_count,
            "c2_active_trend_pct": kpis.c2_active_trend_pct,
            "malicious_url_count": kpis.malicious_url_count,
            "malicious_url_trend_pct": kpis.malicious_url_trend_pct,
            "threatfox_malware_families_count": kpis.threatfox_malware_families_count,
            "threatfox_malware_families_trend_pct": kpis.threatfox_malware_families_trend_pct,
            "ransomware_active_groups_count": kpis.ransomware_active_groups_count,
            "ransomware_active_groups_trend_pct": kpis.ransomware_active_groups_trend_pct,
            "ransomware_victim_count": kpis.ransomware_victim_count,
            "ransomware_victim_count_trend_pct": kpis.ransomware_victim_count_trend_pct,
        },
        "cves": top_cves,
        "malicious_ips": top_ips,
        "malicious_urls": malicious_url_items,
        "malicious_url_pool_total": malicious_url_pool_total,
        # groups[].sparkline_weekly_counts est une liste de nombres bruts, jamais un SVG
        # pré-rendu — PDF et frontend génèrent chacun leur propre visuel depuis ces mêmes
        # chiffres (cf. décision produit "les deux rendus ne partagent jamais une image").
        "ransomware_watch": ransomware_watch,
        "top_countries": kpis.top_countries,
        "top_vendors": kpis.top_vendors,
        "cwe_breakdown": [{"cwe": row["cwe_id"], "count": row["count"]} for row in kpis.cwe_distribution],
        # Mêmes helpers que pdf_context.py::build_pdf_context — mêmes chiffres affichés côté
        # PDF et côté JSON public, aucune logique d'agrégation dupliquée (cf. CDC json_writer.py).
        "c2_malware_family_breakdown": _chip_breakdown(c2_items, "malware_family", "malware_family", _TOP_N_COUNTRIES),
        "c2_top_asn": _chip_breakdown(c2_items, "asn", "asn", _TOP_N_COUNTRIES),
        "c2_cross_confirmed": _c2_cross_confirmed(c2_items, sources_status),
        "malicious_url_threat_type_breakdown": _chip_breakdown(
            malicious_url_items, "threat_type", "threat_type", _TOP_N_COUNTRIES
        ),
        "pipeline_duration_seconds": pipeline_duration_seconds,
        "generated_at": datetime.now(UTC).isoformat(),
        "schema_version": SCHEMA_VERSION,
    }


def write_report_json(payload: dict, period_end: str, run_id: str, base_path: str, storage_options: dict | None) -> str:
    path = f"{base_path}/reports/report-{period_end}-{run_id}.json"
    body = json.dumps(payload)
    if storage_options is None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(body, encoding="utf-8")
    else:
        import fsspec

        fs = fsspec.filesystem("s3", **storage_options)
        with fs.open(path, "w") as fh:
            fh.write(body)
    return path
