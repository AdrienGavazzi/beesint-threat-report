from __future__ import annotations

import polars as pl


def join_nvd_kev(cve_df: pl.DataFrame, kev_df: pl.DataFrame) -> pl.DataFrame:
    kev_dates = kev_df.select(["cve_id", pl.col("date_added").alias("kev_date_added")])
    return cve_df.join(kev_dates, on="cve_id", how="inner")


def compute_mean_time_to_kev(joined_df: pl.DataFrame) -> float | None:
    if joined_df.height == 0:
        return None
    deltas = (joined_df["kev_date_added"] - joined_df["published_date"]).dt.total_days()
    return round(float(deltas.mean()), 1)


def compute_median_time_to_kev(joined_df: pl.DataFrame) -> float | None:
    if joined_df.height == 0:
        return None
    deltas = (joined_df["kev_date_added"] - joined_df["published_date"]).dt.total_days()
    return round(float(deltas.median()), 1)


def compute_mean_remediation_window_days(kev_df: pl.DataFrame) -> float | None:
    """Moyenne `due_date - date_added` sur TOUTES les entrées KEV du run — contrairement à
    compute_mean_time_to_kev/compute_median_time_to_kev, pas limité aux CVE joints NVD/KEV de la
    même semaine (join_nvd_kev). Toujours disponible dès qu'il y a >= 1 entrée KEV ce run, ce qui
    en fait un complément "toujours peuplé" au gauge MTTK existant (qui reste honnêtement à 0 la
    plupart du temps, cf. CDC Phase P3 — le gauge n'est pas remplacé, cette métrique vit à côté)."""
    if kev_df.height == 0:
        return None
    deltas = (kev_df["due_date"] - kev_df["date_added"]).dt.total_days()
    return round(float(deltas.mean()), 1)
