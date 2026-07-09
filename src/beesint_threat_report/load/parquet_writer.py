from __future__ import annotations

import logging
from pathlib import Path

import fsspec
import polars as pl

logger = logging.getLogger(__name__)


def _get_fs(storage_options: dict | None):
    if storage_options:
        return fsspec.filesystem("s3", **storage_options)
    return fsspec.filesystem("file")


def write_historical_parquet(
    df: pl.DataFrame,
    source: str,
    period_end: str,
    run_id: str,
    base_path: str,
    storage_options: dict | None,
) -> str:
    path = f"{base_path}/history/{source}/period_end={period_end}/run-{run_id}.parquet"
    if storage_options is None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        df.write_parquet(path)
    else:
        # écrit via un fichier fsspec ouvert plutôt que de laisser polars gérer l'URI s3://
        # nativement (son client cloud natif ignore storage_options au format s3fs et
        # n'utilise pas le endpoint_url custom — cohérence avec _write_json/_read_json).
        fs = _get_fs(storage_options)
        with fs.open(path, "wb") as fh:
            df.write_parquet(fh)
    return path


def read_latest_historical_parquet(source: str, base_path: str, storage_options: dict | None) -> pl.DataFrame | None:
    prefix = f"{base_path}/history/{source}"
    fs = _get_fs(storage_options)
    try:
        files = fs.glob(f"{prefix}/period_end=*/run-*.parquet")
    except FileNotFoundError:
        return None
    if not files:
        return None
    # tri lexical : period_end=YYYYMMDD dans le chemin garantit l'ordre chronologique
    latest = sorted(files)[-1]
    try:
        if storage_options is None:
            return pl.read_parquet(latest)
        with fs.open(latest, "rb") as fh:
            return pl.read_parquet(fh)
    except Exception:
        logger.warning("parquet_writer: lecture échouée pour %s, traité comme absent", latest)
        return None
