from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from beesint_threat_report.validate.schemas import (
    FeodoIpRecord,
    KevEntry,
    NvdCveRecord,
    UrlhausEntry,
    validate_batch,
)


def test_nvd_cve_record_valid():
    record = NvdCveRecord(
        cve_id="CVE-2026-10001",
        published_date=datetime(2026, 6, 1, tzinfo=UTC),
        last_modified_date=datetime(2026, 6, 2, tzinfo=UTC),
        cvss_v3_score=9.8,
        cvss_v3_severity="CRITICAL",
        description="desc",
        cwe_ids=["CWE-79"],
        vendor="acme",
        references=["https://example.com"],
    )
    assert record.cve_id == "CVE-2026-10001"
    assert record.published_date.tzinfo is not None


def test_nvd_cve_record_invalid_id_raises():
    with pytest.raises(ValidationError):
        NvdCveRecord(
            cve_id="NOT-A-CVE",
            published_date=datetime(2026, 6, 1),
            last_modified_date=datetime(2026, 6, 2),
            cvss_v3_score=9.8,
            cvss_v3_severity="CRITICAL",
            description="desc",
            cwe_ids=[],
            vendor=None,
            references=[],
        )


def test_nvd_cve_record_naive_datetime_forced_utc():
    record = NvdCveRecord(
        cve_id="CVE-2026-10001",
        published_date=datetime(2026, 6, 1),  # naive
        last_modified_date=datetime(2026, 6, 2),
        cvss_v3_score=None,
        cvss_v3_severity=None,
        description="desc",
        cwe_ids=[],
        vendor=None,
        references=[],
    )
    assert record.published_date.tzinfo == UTC


def test_kev_entry_invalid_cve_id_raises():
    with pytest.raises(ValidationError):
        KevEntry(
            cve_id="BAD-ID",
            vendor_project="Acme",
            product="Widget",
            vulnerability_name="Acme Widget RCE",
            date_added=datetime(2026, 6, 5),
            short_description="desc",
            required_action="patch",
            due_date=datetime(2026, 6, 26),
            known_ransomware_campaign_use="Known",
        )


def test_feodo_ip_record_malformed_ip_raises():
    with pytest.raises(ValidationError):
        FeodoIpRecord(
            ip_address="999.999.999.999",
            port=443,
            status="online",
            malware="Heodo",
            first_seen=datetime(2026, 5, 1),
            last_online=None,
            country="US",
            as_number=64500,
            as_name="EXAMPLE-AS",
        )


def test_feodo_ip_record_valid_ipv6():
    record = FeodoIpRecord(
        ip_address="2001:db8::1",
        port=None,
        status="online",
        malware="Heodo",
        first_seen=datetime(2026, 5, 1),
        last_online=None,
        country="US",
        as_number=None,
        as_name=None,
    )
    assert record.ip_address == "2001:db8::1"


def test_urlhaus_entry_missing_required_field_raises():
    with pytest.raises(ValidationError):
        UrlhausEntry.model_validate(
            {
                "url": "http://evil.example/mal.exe",
                "url_status": "online",
                "date_added": "2026-06-01T10:00:00",
                "threat": "malware_download",
                "tags": [],
                # "host" manquant
                "reporter": "abuse_ch",
            }
        )


def test_validate_batch_mixed_valid_invalid_never_raises():
    raw_items = [
        {
            "cve_id": "CVE-2026-10001",
            "published_date": "2026-06-01T10:00:00",
            "last_modified_date": "2026-06-02T10:00:00",
            "cvss_v3_score": 9.8,
            "cvss_v3_severity": "CRITICAL",
            "description": "desc",
            "cwe_ids": [],
            "vendor": None,
            "references": [],
        },
        {
            "cve_id": "NOT-VALID",
            "published_date": "2026-06-01T10:00:00",
            "last_modified_date": "2026-06-02T10:00:00",
            "cvss_v3_score": 9.8,
            "cvss_v3_severity": "CRITICAL",
            "description": "desc",
            "cwe_ids": [],
            "vendor": None,
            "references": [],
        },
    ]
    valid, rejected = validate_batch(raw_items, NvdCveRecord, source="nvd", run_id="test-run")
    assert len(valid) == 1
    assert len(rejected) == 1
    assert rejected[0]["cve_id"] == "NOT-VALID"
