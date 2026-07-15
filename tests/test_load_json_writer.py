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


def _c2_items() -> list[dict]:
    return [
        {
            "ip_address": "1.1.1.1",
            "malware_family": "Emotet",
            "asn": "AS12345",
            "confirmed_by_spamhaus": True,
            "greynoise_classification": "malicious",
            "shodan_has_data": True,
        },
        {
            "ip_address": "2.2.2.2",
            "malware_family": "Emotet",
            "asn": "AS12345",
            "confirmed_by_spamhaus": False,
            "greynoise_classification": None,
            "shodan_has_data": False,
        },
    ]


def _malicious_url_items() -> list[dict]:
    return [
        {
            "url": "http://evil.example/a",
            "threat_type": "phishing",
            "tags": [],
            "date_added": None,
            "sources": ["urlhaus", "phishtank"],
        },
        {
            "url": "http://evil.example/b",
            "threat_type": "phishing",
            "tags": [],
            "date_added": None,
            "sources": ["urlhaus"],
        },
    ]


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
        sources_status={"nvd": "ok", "kev": "ok", "feodo": "ok", "urlhaus": "ok", "spamhaus_drop": "ok"},
        c2_items=_c2_items(),
        malicious_url_items=_malicious_url_items(),
    )
    json.dumps(payload)  # ne doit pas lever
    assert payload["run_id"] == "run-1"
    assert payload["status"] == "success"
    assert payload["kpis"]["kev_ransomware_flag"] is True
    assert payload["cwe_breakdown"] == [{"cwe": "CWE-79", "count": 2}]
    assert payload["schema_version"] == 1
    assert payload["malicious_urls"] == _malicious_url_items()
    assert payload["c2_malware_family_breakdown"] == [{"malware_family": "Emotet", "count": 2, "pct_of_total": 100.0}]
    assert payload["c2_top_asn"] == [{"asn": "AS12345", "count": 2, "pct_of_total": 100.0}]
    assert payload["c2_cross_confirmed"] == {"confirmed": 1, "total": 2}
    assert payload["malicious_url_threat_type_breakdown"] == [
        {"threat_type": "phishing", "count": 2, "pct_of_total": 100.0}
    ]


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
        c2_items=[],
        malicious_url_items=[],
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
