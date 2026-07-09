from datetime import UTC, datetime, timedelta

import polars as pl

from beesint_threat_report.transform.kpis import ReportKpis, compute_kpis


def test_compute_kpis_cold_start_trend_none():
    cve_df = pl.DataFrame({"cve_id": ["CVE-1", "CVE-2"], "vendor": ["acme", "acme"], "cwe_ids": [["CWE-79"], []]})
    kev_df = pl.DataFrame(
        {
            "cve_id": ["CVE-1"],
            "due_date": [datetime.now(UTC) + timedelta(days=1)],
            "known_ransomware_campaign_use": ["Known"],
        }
    )
    feodo_df = pl.DataFrame({"ip_address": ["1.1.1.1"], "status": ["online"], "country": ["US"]})
    urlhaus_df = pl.DataFrame({"url": ["http://x"], "url_status": ["online"]})

    kpis = compute_kpis(
        cve_df, kev_df, feodo_df, urlhaus_df, mean_time_to_kev=5.0, previous_kpis=None, cve_high_count=3
    )

    assert kpis.cve_critical_count == 2
    assert kpis.cve_critical_trend_pct is None
    assert kpis.cve_high_count == 3
    assert kpis.kev_new_count == 1
    assert kpis.kev_urgent_count == 1
    assert kpis.kev_ransomware_count == 1
    assert kpis.c2_active_count == 1
    assert kpis.malicious_url_count == 1
    assert kpis.top_countries == [{"country": "US", "count": 1}]
    assert kpis.top_vendors == [{"vendor": "acme", "count": 2}]
    assert {"cwe_id": "CWE-79", "count": 1} in kpis.cwe_distribution


def test_compute_kpis_trend_pct_vs_previous():
    kev_empty = pl.DataFrame({"cve_id": [], "due_date": [], "known_ransomware_campaign_use": []})
    feodo_empty = pl.DataFrame({"ip_address": [], "status": [], "country": []})
    urlhaus_empty = pl.DataFrame({"url": [], "url_status": []})

    cve_df = pl.DataFrame({"cve_id": ["CVE-1", "CVE-2", "CVE-3", "CVE-4"], "vendor": [None] * 4, "cwe_ids": [[]] * 4})
    previous = ReportKpis(
        cve_critical_count=2,
        cve_critical_trend_pct=None,
        cve_high_count=0,
        kev_new_count=0,
        kev_urgent_count=0,
        kev_ransomware_count=0,
        mean_time_to_kev_days=None,
        c2_active_count=0,
        malicious_url_count=0,
        top_countries=[],
        top_vendors=[],
        cwe_distribution=[],
    )
    kpis = compute_kpis(cve_df, kev_empty, feodo_empty, urlhaus_empty, None, previous)
    assert kpis.cve_critical_trend_pct == 100.0
