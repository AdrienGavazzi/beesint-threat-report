from datetime import UTC, datetime

import httpx
import pytest
import respx
from conftest import load_fixture

from beesint_threat_report.extract.kev import fetch_kev_feed, filter_new_entries
from beesint_threat_report.validate.schemas import KevEntry, validate_batch

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@pytest.mark.asyncio
async def test_fetch_kev_feed_maps_all_entries_no_temporal_filter():
    fixture = load_fixture("kev_feed.json")
    with respx.mock() as mock:
        mock.get(KEV_URL).mock(return_value=httpx.Response(200, json=fixture))
        async with httpx.AsyncClient() as client:
            result = await fetch_kev_feed(client, KEV_URL)
    assert len(result) == 3
    assert result[0]["cve_id"] == "CVE-2026-10001"
    assert result[0]["known_ransomware_campaign_use"] == "Known"


def test_filter_new_entries_multiple_date_bounds():
    fixture = load_fixture("kev_feed.json")
    raw = [
        {
            "cve_id": item["cveID"],
            "vendor_project": item["vendorProject"],
            "product": item["product"],
            "vulnerability_name": item["vulnerabilityName"],
            "date_added": item["dateAdded"],
            "short_description": item["shortDescription"],
            "required_action": item["requiredAction"],
            "due_date": item["dueDate"],
            "known_ransomware_campaign_use": item["knownRansomwareCampaignUse"],
        }
        for item in fixture["vulnerabilities"]
    ]
    entries, _ = validate_batch(raw, KevEntry, source="kev", run_id="test-run")

    period_start = datetime(2026, 6, 1, tzinfo=UTC)
    period_end = datetime(2026, 6, 8, tzinfo=UTC)
    new_entries = filter_new_entries(entries, period_start, period_end)

    assert {e.cve_id for e in new_entries} == {"CVE-2026-10001", "CVE-2026-20003"}

    narrow_start = datetime(2026, 6, 6, tzinfo=UTC)
    narrow_end = datetime(2026, 6, 6, 23, 59, 59, tzinfo=UTC)
    narrow_entries = filter_new_entries(entries, narrow_start, narrow_end)
    assert {e.cve_id for e in narrow_entries} == {"CVE-2026-20003"}
