from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

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
    is_cold_start: bool = False,
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
            "kev_ransomware_flag": kpis.kev_ransomware_count > 0,
            "mean_time_to_kev_days": kpis.mean_time_to_kev_days,
            "c2_active_count": kpis.c2_active_count,
            "malicious_url_count": kpis.malicious_url_count,
        },
        "cves": top_cves,
        "malicious_ips": top_ips,
        "top_countries": kpis.top_countries,
        "top_vendors": kpis.top_vendors,
        "cwe_breakdown": [{"cwe": row["cwe_id"], "count": row["count"]} for row in kpis.cwe_distribution],
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
