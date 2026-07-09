from datetime import datetime

import polars as pl

from beesint_threat_report.transform.ranking import rank_top_n_cves, rank_top_n_ips


def test_rank_top_n_cves_tie_break_deterministic_order():
    df = pl.DataFrame(
        {
            "cve_id": ["CVE-2026-3", "CVE-2026-1", "CVE-2026-2", "CVE-2026-9"],
            "cvss_v3_score": [9.8, 9.8, 9.8, 7.0],
            "published_date": [
                datetime(2026, 6, 1),
                datetime(2026, 6, 1),
                datetime(2026, 6, 3),
                datetime(2026, 6, 1),
            ],
        }
    )
    result = rank_top_n_cves(df, n=10)
    # 3 CVE à score 9.8 identique : tri secondaire published_date DESC (CVE-2026-2 en tête,
    # seule à avoir 06-03), puis tertiaire cve_id ASC entre CVE-2026-1 et CVE-2026-3 (même date)
    assert result["cve_id"].to_list() == ["CVE-2026-2", "CVE-2026-1", "CVE-2026-3", "CVE-2026-9"]


def test_rank_top_n_cves_n_greater_than_size_returns_all_no_error():
    df = pl.DataFrame(
        {
            "cve_id": ["CVE-2026-1"],
            "cvss_v3_score": [9.0],
            "published_date": [datetime(2026, 6, 1)],
        }
    )
    result = rank_top_n_cves(df, n=100)
    assert result.height == 1


def test_rank_top_n_ips_new_first_then_first_seen_then_ip():
    df = pl.DataFrame(
        {
            "ip_address": ["3.3.3.3", "1.1.1.1", "2.2.2.2"],
            "is_new": [False, True, True],
            "first_seen": [datetime(2026, 6, 5), datetime(2026, 6, 1), datetime(2026, 6, 1)],
        }
    )
    result = rank_top_n_ips(df, n=10)
    assert result["ip_address"].to_list() == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
