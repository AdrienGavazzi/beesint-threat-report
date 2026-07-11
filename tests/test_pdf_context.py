from datetime import datetime

import polars as pl

from beesint_threat_report.load.pdf_context import (
    _build_executive_summary,
    _build_sparkline_svg,
    build_pdf_context,
)
from beesint_threat_report.transform.kpis import ReportKpis


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
        feodo_df=empty_feodo_df,
        c2_items=[],
        malicious_url_items=[],
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
