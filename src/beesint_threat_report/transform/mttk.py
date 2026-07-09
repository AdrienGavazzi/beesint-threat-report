from __future__ import annotations

import polars as pl


def join_nvd_kev(cve_df: pl.DataFrame, kev_df: pl.DataFrame) -> pl.DataFrame:
    kev_dates = kev_df.select(["cve_id", pl.col("date_added").alias("kev_date_added")])
    return cve_df.join(kev_dates, on="cve_id", how="inner")


def compute_mean_time_to_kev(joined_df: pl.DataFrame) -> float | None:
    if joined_df.height == 0:
        return None
    deltas = (joined_df["kev_date_added"] - joined_df["published_date"]).dt.total_days()
    return float(deltas.mean())


def compute_median_time_to_kev(joined_df: pl.DataFrame) -> float | None:
    if joined_df.height == 0:
        return None
    deltas = (joined_df["kev_date_added"] - joined_df["published_date"]).dt.total_days()
    return float(deltas.median())
