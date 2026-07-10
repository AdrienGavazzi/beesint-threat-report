from __future__ import annotations

import logging

from beesint_threat_report.transform.kpis import ReportKpis

logger = logging.getLogger(__name__)


def log_run_summary(run_id: str, duration_seconds: float, sources_status: dict[str, str], kpis: ReportKpis) -> None:
    sources = " ".join(f"{name}={status}" for name, status in sources_status.items())
    logger.info(
        "run %s done in %.1fs - sources[%s] cve_critical=%d kev_new=%d c2_active=%d malicious_urls=%d",
        run_id,
        duration_seconds,
        sources,
        kpis.cve_critical_count,
        kpis.kev_new_count,
        kpis.c2_active_count,
        kpis.malicious_url_count,
    )


def sentry_breadcrumb_run_step(step: str, status: str, details: dict | None = None) -> None:
    logger.info("%s: %s", step, status)
    try:
        import sentry_sdk

        sentry_sdk.add_breadcrumb(category="etl", message=step, data={"status": status, **(details or {})})
    except Exception:
        pass
