from __future__ import annotations

import logging

from beesint_threat_report.transform.kpis import ReportKpis

logger = logging.getLogger(__name__)


def log_run_summary(run_id: str, duration_seconds: float, sources_status: dict[str, str], kpis: ReportKpis) -> None:
    logger.info(
        "threat-report run summary",
        extra={
            "run_id": run_id,
            "duration_seconds": duration_seconds,
            "sources_status": sources_status,
            "cve_critical_count": kpis.cve_critical_count,
            "kev_new_count": kpis.kev_new_count,
            "c2_active_count": kpis.c2_active_count,
            "malicious_url_count": kpis.malicious_url_count,
        },
    )


def sentry_breadcrumb_run_step(step: str, status: str, details: dict | None = None) -> None:
    try:
        import sentry_sdk

        sentry_sdk.add_breadcrumb(category="etl", message=step, data={"status": status, **(details or {})})
    except Exception:
        pass
