from datetime import datetime

import polars as pl

from beesint_threat_report.transform.mttk import (
    compute_mean_remediation_window_days,
    compute_mean_time_to_kev,
    join_nvd_kev,
)


def test_join_and_mean_time_partial_overlap():
    cve_df = pl.DataFrame(
        {
            "cve_id": ["CVE-2026-1", "CVE-2026-2", "CVE-2026-3"],
            "published_date": [datetime(2026, 6, 1), datetime(2026, 6, 2), datetime(2026, 6, 3)],
        }
    )
    kev_df = pl.DataFrame(
        {
            "cve_id": ["CVE-2026-1", "CVE-2026-2"],
            "date_added": [datetime(2026, 6, 5), datetime(2026, 6, 8)],
        }
    )
    joined = join_nvd_kev(cve_df, kev_df)
    assert joined.height == 2

    mean_days = compute_mean_time_to_kev(joined)
    # CVE-1: 4 jours, CVE-2: 6 jours -> moyenne 5.0
    assert mean_days == 5.0


def test_compute_mean_time_to_kev_empty_join_returns_none():
    empty = pl.DataFrame({"cve_id": [], "published_date": [], "kev_date_added": []}).cast(
        {"published_date": pl.Datetime, "kev_date_added": pl.Datetime}
    )
    assert compute_mean_time_to_kev(empty) is None


def test_compute_mean_remediation_window_days_uses_all_kev_entries_not_just_joined():
    # Contrairement à compute_mean_time_to_kev (limité aux CVE joints NVD/KEV de la même semaine),
    # cette métrique porte sur TOUTES les entrées KEV du run, même sans correspondance NVD locale.
    kev_df = pl.DataFrame(
        {
            "cve_id": ["CVE-2026-1", "CVE-2026-2", "CVE-2026-3"],
            "date_added": [datetime(2026, 6, 1), datetime(2026, 6, 2), datetime(2026, 6, 3)],
            "due_date": [datetime(2026, 6, 15), datetime(2026, 6, 9), datetime(2026, 6, 24)],
        }
    )
    # deltas: 14, 7, 21 -> moyenne 14.0
    assert compute_mean_remediation_window_days(kev_df) == 14.0


def test_compute_mean_remediation_window_days_empty_kev_returns_none():
    empty = pl.DataFrame({"cve_id": [], "date_added": [], "due_date": []}).cast(
        {"date_added": pl.Datetime, "due_date": pl.Datetime}
    )
    assert compute_mean_remediation_window_days(empty) is None
