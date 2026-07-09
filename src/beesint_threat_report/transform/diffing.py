from __future__ import annotations

import logging

import polars as pl

from beesint_threat_report.config import Settings, resolve_base_path, resolve_storage_options
from beesint_threat_report.load.parquet_writer import read_latest_historical_parquet

logger = logging.getLogger(__name__)


def diff_snapshots(current_df: pl.DataFrame, previous_df: pl.DataFrame | None, key_column: str) -> pl.DataFrame:
    if previous_df is None or previous_df.height == 0:
        return current_df.with_columns(pl.lit(True).alias("is_new"))
    previous_keys = set(previous_df[key_column].to_list())
    return current_df.with_columns(pl.col(key_column).is_in(previous_keys).not_().alias("is_new"))


def load_previous_snapshot(manifest: dict | None, source: str, settings: Settings) -> pl.DataFrame | None:
    if manifest is None:
        return None
    base_path = resolve_base_path(settings)
    storage_options = resolve_storage_options(settings)
    try:
        return read_latest_historical_parquet(source, base_path, storage_options)
    except Exception:
        logger.warning("diffing: snapshot précédent illisible pour %s, traité comme cold start", source)
        return None
