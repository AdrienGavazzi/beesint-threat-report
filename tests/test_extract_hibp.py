from datetime import UTC, datetime

import httpx
import pytest
import respx
from conftest import load_fixture

from beesint_threat_report.extract.hibp import fetch_hibp_breaches, filter_new_breaches
from beesint_threat_report.validate.schemas import BreachEntry, validate_batch

HIBP_URL = "https://haveibeenpwned.com/api/v3/breaches"


@pytest.mark.asyncio
async def test_fetch_hibp_breaches_maps_all_entries_no_temporal_filter():
    fixture = load_fixture("hibp_breaches.json")
    with respx.mock() as mock:
        mock.get(HIBP_URL).mock(return_value=httpx.Response(200, json=fixture))
        async with httpx.AsyncClient() as client:
            result = await fetch_hibp_breaches(client, HIBP_URL)
    assert len(result) == 2
    assert result[0]["name"] == "ExampleCorp"
    assert result[0]["pwn_count"] == 1200000


def test_filter_new_breaches_only_keeps_entries_in_window():
    fixture = load_fixture("hibp_breaches.json")
    raw = [
        {
            "name": item["Name"],
            "title": item["Title"],
            "domain": item["Domain"],
            "breach_date": item["BreachDate"],
            "added_date": item["AddedDate"],
            "pwn_count": item["PwnCount"],
            "data_classes": item["DataClasses"],
            "is_verified": item["IsVerified"],
            "is_sensitive": item["IsSensitive"],
            "description": item["Description"],
        }
        for item in fixture
    ]
    entries, _ = validate_batch(raw, BreachEntry, source="hibp", run_id="test-run")

    period_start = datetime(2026, 6, 1, tzinfo=UTC)
    period_end = datetime(2026, 6, 8, tzinfo=UTC)
    new_entries = filter_new_breaches(entries, period_start, period_end)

    assert {e.name for e in new_entries} == {"ExampleCorp"}
