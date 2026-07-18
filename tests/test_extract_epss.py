import httpx
import pytest
import respx

from beesint_threat_report.extract.epss import fetch_epss_scores

BASE_URL = "https://api.first.org/data/v1/epss"


@pytest.mark.asyncio
async def test_fetch_epss_scores_parses_string_decimals_to_float():
    with respx.mock() as mock:
        mock.get(BASE_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "status": "OK",
                    "data": [
                        {
                            "cve": "CVE-2021-44228",
                            "epss": "0.999990000",
                            "percentile": "1.000000000",
                            "date": "2026-07-18",
                        }
                    ],
                },
            )
        )
        async with httpx.AsyncClient() as client:
            result = await fetch_epss_scores(client, ["CVE-2021-44228"], BASE_URL)

    assert result == [{"cve_id": "CVE-2021-44228", "epss_score": 0.99999, "epss_percentile": 1.0}]


@pytest.mark.asyncio
async def test_fetch_epss_scores_unknown_cve_degrades_to_empty_list():
    with respx.mock() as mock:
        mock.get(BASE_URL).mock(return_value=httpx.Response(200, json={"status": "OK", "data": []}))
        async with httpx.AsyncClient() as client:
            result = await fetch_epss_scores(client, ["CVE-9999-99999"], BASE_URL)

    assert result == []


@pytest.mark.asyncio
async def test_fetch_epss_scores_empty_cve_list_skips_network_call():
    async with httpx.AsyncClient() as client:
        result = await fetch_epss_scores(client, [], BASE_URL)
    assert result == []


@pytest.mark.asyncio
async def test_fetch_epss_scores_sends_comma_joined_batch_and_explicit_limit():
    with respx.mock() as mock:
        route = mock.get(BASE_URL).mock(return_value=httpx.Response(200, json={"status": "OK", "data": []}))
        async with httpx.AsyncClient() as client:
            await fetch_epss_scores(client, ["CVE-2021-44228", "CVE-2024-3400"], BASE_URL)

    request = route.calls[0].request
    assert request.url.params["cve"] == "CVE-2021-44228,CVE-2024-3400"
    assert request.url.params["limit"] == "200"
