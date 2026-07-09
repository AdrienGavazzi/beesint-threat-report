import json

from beesint_threat_report.load.json_writer import build_report_payload, write_report_json
from beesint_threat_report.transform.kpis import ReportKpis


def _kpis() -> ReportKpis:
    return ReportKpis(
        cve_critical_count=2,
        cve_critical_trend_pct=None,
        cve_high_count=5,
        kev_new_count=1,
        kev_urgent_count=1,
        kev_ransomware_count=1,
        mean_time_to_kev_days=4.5,
        c2_active_count=1,
        malicious_url_count=2,
        top_countries=[{"country": "US", "count": 3}],
        top_vendors=[{"vendor": "acme", "count": 2}],
        cwe_distribution=[{"cwe_id": "CWE-79", "count": 2}],
    )


def test_build_report_payload_is_json_serializable_and_matches_contract():
    payload = build_report_payload(
        run_id="run-1",
        period_start="2026-06-01T00:00:00+00:00",
        period_end="2026-06-08T00:00:00+00:00",
        status="success",
        kpis=_kpis(),
        top_cves=[{"cve_id": "CVE-2026-1"}],
        top_ips=[{"ip": "1.1.1.1"}],
        pipeline_duration_seconds=12.3,
        sources_status={"nvd": "ok", "kev": "ok", "feodo": "ok", "urlhaus": "ok"},
    )
    json.dumps(payload)  # ne doit pas lever
    assert payload["run_id"] == "run-1"
    assert payload["status"] == "success"
    assert payload["kpis"]["kev_ransomware_flag"] is True
    assert payload["cwe_breakdown"] == [{"cwe": "CWE-79", "count": 2}]
    assert payload["schema_version"] == 1


def test_write_report_json_correct_path(tmp_path):
    payload = build_report_payload(
        run_id="run-1",
        period_start="2026-06-01T00:00:00+00:00",
        period_end="2026-06-08T00:00:00+00:00",
        status="success",
        kpis=_kpis(),
        top_cves=[],
        top_ips=[],
        pipeline_duration_seconds=1.0,
        sources_status={},
    )
    written = write_report_json(
        payload,
        period_end="20260608",
        run_id="run-1",
        base_path=str(tmp_path),
        storage_options=None,
    )
    assert written.endswith("reports/report-20260608-run-1.json")
    assert json.loads((tmp_path / "reports" / "report-20260608-run-1.json").read_text()) == payload
