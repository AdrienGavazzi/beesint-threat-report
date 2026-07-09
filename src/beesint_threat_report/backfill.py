from __future__ import annotations

import argparse
import asyncio
import logging
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx

from beesint_threat_report.config import load_settings, resolve_base_path, resolve_storage_options
from beesint_threat_report.extract import kev, nvd
from beesint_threat_report.load.parquet_writer import write_historical_parquet
from beesint_threat_report.orchestrate import (
    _CVE_EMPTY_SCHEMA,
    _KEV_EMPTY_SCHEMA,
    _records_to_frame,
)
from beesint_threat_report.transform import dedup
from beesint_threat_report.validate.frames import validate_cve_frame, validate_kev_frame
from beesint_threat_report.validate.schemas import KevEntry, NvdCveRecord, validate_batch

logger = logging.getLogger(__name__)


def _rolling_windows(periods_back: int, now: datetime) -> list[tuple[datetime, datetime]]:
    windows = [(now - timedelta(days=7 * (i + 1)), now - timedelta(days=7 * i)) for i in range(periods_back)]
    return list(reversed(windows))  # plus ancienne en premier, la plus récente en dernier


async def backfill(periods_back: int = 8) -> None:
    settings = load_settings()
    base_path = resolve_base_path(settings)
    storage_options = resolve_storage_options(settings)
    now = datetime.now(UTC)
    windows = _rolling_windows(periods_back, now)

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            kev_raw = await kev.fetch_kev_feed(client, settings.kev_feed_url)
            kev_valid, _ = validate_batch(kev_raw, KevEntry, source="kev", run_id="backfill")
            kev_deduped = dedup.dedup_kev(kev_valid)
        except Exception:
            logger.exception("backfill: pull KEV complet échoué, aucune fenêtre KEV ne sera écrite")
            kev_deduped = []

        logger.warning(
            "backfill: FeodoTracker/URLhaus non disponibles en historique — "
            "backfill non disponible pour ces sources, limite assumée (cf. CDC §7)"
        )

        for period_start, period_end in windows:
            run_id = str(uuid4())
            period_end_str = period_end.strftime("%Y%m%d")

            try:
                nvd_raw = await nvd.fetch_critical_cves(
                    client,
                    period_start,
                    period_end,
                    settings.nvd_api_key,
                    settings.max_results_nvd,
                    settings.nvd_base_url,
                )
                nvd_valid, _ = validate_batch(nvd_raw, NvdCveRecord, source="nvd", run_id=run_id)
                nvd_deduped = dedup.dedup_cves(nvd_valid)
                cve_df = _records_to_frame(nvd_deduped, _CVE_EMPTY_SCHEMA)
                if cve_df.height:
                    cve_df = validate_cve_frame(cve_df)
                write_historical_parquet(cve_df, "nvd", period_end_str, run_id, base_path, storage_options)
            except Exception:
                logger.exception("backfill: fenêtre NVD %s→%s échouée, fenêtre suivante", period_start, period_end)

            kev_window_entries = kev.filter_new_entries(kev_deduped, period_start, period_end)
            kev_df = _records_to_frame(kev_window_entries, _KEV_EMPTY_SCHEMA)
            if kev_df.height:
                kev_df = validate_kev_frame(kev_df)
            write_historical_parquet(kev_df, "kev", period_end_str, run_id, base_path, storage_options)

            logger.info("backfill: fenêtre %s→%s écrite (run_id=%s)", period_start, period_end, run_id)


def main() -> None:
    from dotenv import load_dotenv

    load_dotenv()
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser()
    parser.add_argument("--periods-back", type=int, default=8)
    args = parser.parse_args()
    asyncio.run(backfill(periods_back=args.periods_back))


if __name__ == "__main__":
    main()
