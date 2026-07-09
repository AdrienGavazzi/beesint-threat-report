from datetime import UTC, datetime
from types import SimpleNamespace

from beesint_threat_report.transform.dedup import (
    dedup_cves,
    dedup_feodo,
    dedup_kev,
    dedup_urlhaus,
)
from beesint_threat_report.validate.schemas import FeodoIpRecord, KevEntry, NvdCveRecord, UrlhausEntry


def _cve(cve_id: str, last_modified: str) -> NvdCveRecord:
    return NvdCveRecord(
        cve_id=cve_id,
        published_date=datetime(2026, 6, 1, tzinfo=UTC),
        last_modified_date=datetime.fromisoformat(last_modified).replace(tzinfo=UTC),
        cvss_v3_score=9.0,
        cvss_v3_severity="CRITICAL",
        description="desc",
        cwe_ids=[],
        vendor=None,
        references=[],
    )


def test_dedup_cves_exact_duplicates_and_business_key_keeps_latest_modified():
    older = _cve("CVE-2026-10001", "2026-06-01T00:00:00")
    newer = _cve("CVE-2026-10001", "2026-06-05T00:00:00")
    other = _cve("CVE-2026-10002", "2026-06-01T00:00:00")

    result = dedup_cves([older, newer, other])

    assert len(result) == 2
    kept = {r.cve_id: r for r in result}
    assert kept["CVE-2026-10001"].last_modified_date == newer.last_modified_date


def test_dedup_kev_by_cve_id():
    entry_kwargs = dict(
        vendor_project="Acme",
        product="Widget",
        vulnerability_name="RCE",
        date_added=datetime(2026, 6, 5, tzinfo=UTC),
        short_description="desc",
        required_action="patch",
        due_date=datetime(2026, 6, 26, tzinfo=UTC),
        known_ransomware_campaign_use="Known",
    )
    a = KevEntry(cve_id="CVE-2026-10001", **entry_kwargs)
    b = KevEntry(cve_id="CVE-2026-10001", **entry_kwargs)
    c = KevEntry(cve_id="CVE-2026-10002", **entry_kwargs)
    result = dedup_kev([a, b, c])
    assert {r.cve_id for r in result} == {"CVE-2026-10001", "CVE-2026-10002"}


def test_dedup_feodo_by_ip_address():
    a = FeodoIpRecord(
        ip_address="203.0.113.10",
        port=443,
        status="online",
        malware="Heodo",
        first_seen=datetime(2026, 5, 1, tzinfo=UTC),
        last_online=None,
        country="US",
        as_number=1,
        as_name="AS1",
    )
    b = a.model_copy()
    result = dedup_feodo([a, b])
    assert len(result) == 1


def test_dedup_urlhaus_by_url():
    a = UrlhausEntry(
        url="http://evil.example/mal.exe",
        url_status="online",
        date_added=datetime(2026, 6, 1, tzinfo=UTC),
        threat="malware_download",
        tags=[],
        host="evil.example",
        reporter=None,
    )
    b = a.model_copy()
    result = dedup_urlhaus([a, b])
    assert len(result) == 1


def test_dedup_missing_key_discarded_without_crash():
    valid = _cve("CVE-2026-10001", "2026-06-01T00:00:00")
    broken = SimpleNamespace(cve_id=None, last_modified_date=datetime.now(UTC))
    result = dedup_cves([valid, broken])
    assert result == [valid]
