from datetime import UTC, datetime

import polars as pl

from beesint_threat_report.load.pdf_context import (
    _build_executive_summary,
    _build_multi_donut_svg,
    _build_sparkline_svg,
    _c2_cross_confirmed,
    _format_breach_count,
    _open_ports_breakdown,
    build_breach_items,
    build_c2_items,
    build_malicious_url_items,
    build_pdf_context,
)
from beesint_threat_report.transform.kpis import ReportKpis
from beesint_threat_report.validate.schemas import BreachEntry


def _kpis(**overrides) -> ReportKpis:
    base = dict(
        cve_critical_count=11,
        cve_critical_trend_pct=None,
        cve_high_count=5,
        kev_new_count=4,
        kev_urgent_count=0,
        kev_ransomware_count=0,
        mean_time_to_kev_days=6.3,
        c2_active_count=1,
        malicious_url_count=14883,
        top_countries=[],
        top_vendors=[],
        cwe_distribution=[],
        kev_new_trend_pct=None,
        c2_active_trend_pct=None,
        malicious_url_trend_pct=None,
    )
    base.update(overrides)
    return ReportKpis(**base)


def test_build_sparkline_svg_none_below_two_points():
    assert _build_sparkline_svg([]) is None
    assert _build_sparkline_svg([5]) is None


def test_build_sparkline_svg_renders_polyline_for_normal_series():
    svg = _build_sparkline_svg([2, 5, 3, 8])
    assert svg is not None
    assert "<svg" in svg
    assert "<polyline" in svg
    assert "points=" in svg


def test_build_sparkline_svg_flat_series_does_not_divide_by_zero():
    svg = _build_sparkline_svg([4, 4, 4])
    assert svg is not None
    assert "<polyline" in svg


def test_build_executive_summary_mentions_core_counts():
    summary = _build_executive_summary(_kpis(), is_cold_start=False, sources_status={"nvd": "ok"})
    assert "11" in summary
    assert "4" in summary
    assert "1" in summary


def test_build_executive_summary_cold_start_omits_trend_language():
    summary = _build_executive_summary(
        _kpis(cve_critical_trend_pct=50.0), is_cold_start=True, sources_status={"nvd": "ok"}
    )
    assert "from last week" not in summary


def test_build_executive_summary_ransomware_and_urgent_flags():
    summary = _build_executive_summary(
        _kpis(kev_ransomware_count=1, kev_urgent_count=2), is_cold_start=False, sources_status={"nvd": "ok"}
    )
    assert "ransomware" in summary
    assert "patching within 7 days" in summary


def test_build_executive_summary_notes_degraded_source():
    summary = _build_executive_summary(_kpis(), is_cold_start=False, sources_status={"nvd": "ok", "kev": "failed"})
    assert "kev" in summary
    assert "did not respond normally" in summary


def test_build_pdf_context_surfaces_new_fields():
    empty_kev_df = pl.DataFrame({"cve_id": [], "due_date": [], "known_ransomware_campaign_use": []})
    empty_feodo_df = pl.DataFrame({"ip_address": [], "status": [], "country": []})

    context = build_pdf_context(
        run_id="run-1",
        period_start=datetime(2026, 7, 2),
        period_end=datetime(2026, 7, 9),
        generated_at=datetime(2026, 7, 9),
        kpis=_kpis(),
        critical_items=[],
        kev_df=empty_kev_df,
        mttk_median_days=5.0,
        mttk_sample_size=3,
        kev_remediation_window_days=None,
        feodo_df=empty_feodo_df,
        c2_items=[],
        malicious_url_items=[],
        breach_items=[],
        pipeline_duration_seconds=8.2,
        sources_status={"nvd": "ok", "threatfox": "skipped:no_auth_key"},
        is_cold_start=False,
        history_entries=[
            {
                "period_end": "2026-06-25",
                "cve_critical_count": 8,
                "kev_new_count": 2,
                "c2_active_count": 2,
                "malicious_url_count": 10000,
            },
            {
                "period_end": "2026-07-02",
                "cve_critical_count": 9,
                "kev_new_count": 3,
                "c2_active_count": 1,
                "malicious_url_count": 12000,
            },
        ],
    )

    assert context["executive_summary"]
    assert {"name": "nvd", "status": "ok"} in context["sources_status"]
    assert context["threatfox"]["enabled"] is False
    assert context["kev"]["trend_pct"] is None
    assert context["cve"]["sparkline"] is not None


# ---- build_c2_items: passthrough des champs d'enrichissement (Shodan/Spamhaus/GreyNoise) ----


def test_build_c2_items_carries_new_enrichment_fields():
    top_ips = [
        {
            "ip": "1.1.1.1",
            "country": "US",
            "asn": "AS13335",
            "malware": "Heodo",
            "first_seen": "2026-07-01",
            "last_seen": "2026-07-08",
            "lat": 1.0,
            "lon": 2.0,
            "open_ports": [22, 443],
            "known_cves": ["CVE-2024-0001"],
            "confirmed_by_spamhaus": True,
            "greynoise_classification": "malicious",
            "shodan_has_data": True,
        }
    ]
    items = build_c2_items(top_ips)
    assert items[0]["open_ports"] == [22, 443]
    assert items[0]["known_cves"] == ["CVE-2024-0001"]
    assert items[0]["confirmed_by_spamhaus"] is True
    assert items[0]["greynoise_classification"] == "malicious"
    assert items[0]["shodan_has_data"] is True


def test_build_c2_items_defaults_when_enrichment_missing():
    items = build_c2_items([{"ip": "2.2.2.2"}])
    assert items[0]["open_ports"] == []
    assert items[0]["known_cves"] == []
    assert items[0]["confirmed_by_spamhaus"] is False
    assert items[0]["greynoise_classification"] is None
    assert items[0]["shodan_has_data"] is False


# ---- build_malicious_url_items: champ "sources" (merge PhishTank) --------------------------


def test_build_malicious_url_items_carries_sources():
    df = pl.DataFrame(
        {
            "url": ["http://a.example"],
            "threat": ["phishing"],
            "tags": [["x"]],
            "date_added": [datetime(2026, 7, 1)],
            "sources": [["urlhaus", "phishtank"]],
        }
    )
    items = build_malicious_url_items(df)
    assert items[0]["sources"] == ["urlhaus", "phishtank"]


def test_build_malicious_url_items_defaults_sources_to_urlhaus_when_column_absent():
    df = pl.DataFrame(
        {
            "url": ["http://a.example"],
            "threat": ["phishing"],
            "tags": [["x"]],
            "date_added": [datetime(2026, 7, 1)],
        }
    )
    items = build_malicious_url_items(df)
    assert items[0]["sources"] == ["urlhaus"]


# ---- _open_ports_breakdown -------------------------------------------------------------


def test_open_ports_breakdown_returns_empty_below_min_ips():
    c2_items = [{"open_ports": [22, 443]}, {"open_ports": []}]  # 1 seule IP avec des ports
    assert _open_ports_breakdown(c2_items, n=10) == []


def test_open_ports_breakdown_aggregates_across_enough_ips():
    c2_items = [
        {"open_ports": [22, 443]},
        {"open_ports": [443]},
        {"open_ports": [443, 8080]},
    ]
    result = _open_ports_breakdown(c2_items, n=10)
    ports_by_count = {row["port"]: row["count"] for row in result}
    assert ports_by_count[443] == 3
    assert ports_by_count[22] == 1


# ---- _c2_cross_confirmed -----------------------------------------------------------------


def test_c2_cross_confirmed_none_when_no_enrichment_source_ran():
    c2_items = [{"confirmed_by_spamhaus": True, "greynoise_classification": "malicious", "shodan_has_data": True}]
    result = _c2_cross_confirmed(
        c2_items,
        sources_status={"shodan_internetdb": "failed", "spamhaus_drop": "failed", "greynoise": "skipped:no_api_key"},
    )
    assert result is None


def test_c2_cross_confirmed_none_when_no_c2_items():
    result = _c2_cross_confirmed([], sources_status={"spamhaus_drop": "ok"})
    assert result is None


def test_c2_cross_confirmed_counts_items_with_two_plus_signals():
    c2_items = [
        {"confirmed_by_spamhaus": True, "greynoise_classification": "malicious", "shodan_has_data": True},  # 3 signaux
        {"confirmed_by_spamhaus": True, "greynoise_classification": None, "shodan_has_data": False},  # 1 signal
        {
            "confirmed_by_spamhaus": False,
            "greynoise_classification": "unknown",
            "shodan_has_data": True,
        },  # 1 signal (unknown ne compte pas)
    ]
    result = _c2_cross_confirmed(
        c2_items, sources_status={"spamhaus_drop": "ok", "greynoise": "ok", "shodan_internetdb": "ok"}
    )
    assert result == {"confirmed": 1, "total": 3}


def test_c2_cross_confirmed_greynoise_unknown_is_not_a_signal():
    c2_items = [{"confirmed_by_spamhaus": True, "greynoise_classification": "unknown", "shodan_has_data": False}]
    result = _c2_cross_confirmed(c2_items, sources_status={"greynoise": "ok"})
    assert result == {"confirmed": 0, "total": 1}


# ---- executive summary: nouvelle phrase cross-confirmed -----------------------------------


def test_build_executive_summary_omits_cross_confirmed_sentence_when_none():
    summary = _build_executive_summary(
        _kpis(), is_cold_start=False, sources_status={"nvd": "ok"}, c2_cross_confirmed=None
    )
    assert "independently confirmed" not in summary


def test_build_executive_summary_includes_cross_confirmed_sentence_when_present():
    summary = _build_executive_summary(
        _kpis(), is_cold_start=False, sources_status={"nvd": "ok"}, c2_cross_confirmed={"confirmed": 2, "total": 5}
    )
    assert "2 of this week's active C2 servers were independently confirmed by more than one threat feed." in summary


def test_build_executive_summary_cross_confirmed_singular_noun_and_verb():
    summary = _build_executive_summary(
        _kpis(), is_cold_start=False, sources_status={"nvd": "ok"}, c2_cross_confirmed={"confirmed": 1, "total": 5}
    )
    assert "1 of this week's active C2 server was independently confirmed" in summary


# ---- Breaches This Week (CDC Phase P5) --------------------------------------------------------


def _breach_entry(**overrides) -> BreachEntry:
    base = dict(
        name="ExampleCorp",
        title="ExampleCorp",
        domain="example.com",
        breach_date=datetime(2026, 6, 1, tzinfo=UTC),
        added_date=datetime(2026, 6, 5, tzinfo=UTC),
        pwn_count=1_200_000,
        data_classes=["Email addresses", "Passwords"],
        is_verified=True,
        is_sensitive=False,
        description="Example breach description.",
    )
    base.update(overrides)
    return BreachEntry(**base)


def test_format_breach_count_thresholds():
    assert _format_breach_count(500) == "500"
    assert _format_breach_count(1_500) == "2K"
    assert _format_breach_count(2_500_000) == "2.5M"
    assert _format_breach_count(3_000_000_000) == "3.0B"


def test_build_breach_items_computes_severity_and_formats_pwn_count():
    items = build_breach_items([_breach_entry()], breachdirectory_count=0)
    assert items[0]["severity"] == "CRITICAL"
    assert items[0]["pwn_count_formatted"] == "1.2M"
    assert items[0]["name"] == "ExampleCorp"


def test_build_breach_items_only_spotlight_gets_breachdirectory_count():
    items = build_breach_items(
        [_breach_entry(name="First"), _breach_entry(name="Second", pwn_count=100)], breachdirectory_count=7
    )
    assert items[0]["breachdirectory_count"] == 7
    assert items[1]["breachdirectory_count"] is None


def test_build_breach_items_truncates_long_description():
    long_desc = "x" * 500
    items = build_breach_items([_breach_entry(description=long_desc)], breachdirectory_count=0)
    assert len(items[0]["description"]) == 140
    assert items[0]["description"].endswith("...")


def test_build_multi_donut_svg_none_when_total_zero():
    assert _build_multi_donut_svg([], "BREACHES") is None
    assert _build_multi_donut_svg([(0, "#EF4444")], "BREACHES") is None


def test_build_multi_donut_svg_renders_one_arc_per_nonzero_segment():
    svg = _build_multi_donut_svg([(2, "#EF4444"), (0, "#F59E0B"), (1, "#22C55E")], "BREACHES")
    assert svg is not None
    # 1 <circle> arc par segment non-nul (le segment à count=0 est sauté) + le total au centre.
    assert svg.count("<circle") == 2
    assert "BREACHES" in svg
    assert ">3<" in svg  # total au centre (2 + 0 + 1)
