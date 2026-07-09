from datetime import UTC, datetime

import httpx
import pytest
import respx
from conftest import load_fixture

from beesint_threat_report.extract.nvd import (
    _build_headers,
    count_high_severity_cves,
    fetch_critical_cves,
)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

PERIOD_START = datetime(2026, 6, 1, tzinfo=UTC)
PERIOD_END = datetime(2026, 6, 8, tzinfo=UTC)


@pytest.mark.asyncio
async def test_fetch_critical_cves_pagination_normale():
    fixture = load_fixture("nvd_response.json")
    with respx.mock(base_url=NVD_URL) as mock:
        mock.get("").mock(return_value=httpx.Response(200, json=fixture))
        async with httpx.AsyncClient() as client:
            result = await fetch_critical_cves(
                client, PERIOD_START, PERIOD_END, api_key=None, max_results=2000, base_url=NVD_URL
            )
    assert len(result) == 2
    assert result[0]["cve_id"] == "CVE-2026-10001"
    assert result[0]["cvss_v3_score"] == 9.8
    assert result[0]["vendor"] == "acme"
    assert result[0]["cwe_ids"] == ["CWE-79"]


@pytest.mark.asyncio
async def test_fetch_critical_cves_max_results_cap_no_exception():
    fixture = load_fixture("nvd_response.json")
    with respx.mock(base_url=NVD_URL) as mock:
        mock.get("").mock(return_value=httpx.Response(200, json=fixture))
        async with httpx.AsyncClient() as client:
            result = await fetch_critical_cves(
                client, PERIOD_START, PERIOD_END, api_key=None, max_results=1, base_url=NVD_URL
            )
    assert len(result) == 1


@pytest.mark.asyncio
async def test_fetch_critical_cves_429_then_success_retries():
    fixture = load_fixture("nvd_response.json")
    with respx.mock(base_url=NVD_URL) as mock:
        route = mock.get("")
        route.side_effect = [
            httpx.Response(429),
            httpx.Response(429),
            httpx.Response(200, json=fixture),
        ]
        async with httpx.AsyncClient() as client:
            result = await fetch_critical_cves(
                client, PERIOD_START, PERIOD_END, api_key=None, max_results=2000, base_url=NVD_URL
            )
    assert len(result) == 2
    assert route.call_count == 3


def test_build_headers_with_api_key():
    assert _build_headers("secret") == {"apiKey": "secret"}


def test_build_headers_without_api_key():
    assert _build_headers(None) == {}


@pytest.mark.asyncio
async def test_count_high_severity_cves_reads_total_results_only():
    with respx.mock(base_url=NVD_URL) as mock:
        mock.get("").mock(return_value=httpx.Response(200, json={"totalResults": 42, "vulnerabilities": []}))
        async with httpx.AsyncClient() as client:
            count = await count_high_severity_cves(client, PERIOD_START, PERIOD_END, api_key=None, base_url=NVD_URL)
    assert count == 42
