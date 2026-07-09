from datetime import datetime

import polars as pl

from beesint_threat_report.transform.mttk import compute_mean_time_to_kev, join_nvd_kev


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
