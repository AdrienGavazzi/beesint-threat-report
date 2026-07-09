import httpx
import pytest
import respx
from conftest import load_fixture

from beesint_threat_report.extract.urlhaus import fetch_urlhaus_online
from beesint_threat_report.validate.schemas import UrlhausEntry

URLHAUS_ONLINE_URL = "https://urlhaus.abuse.ch/downloads/json_online/"
URLHAUS_RECENT_URL = "https://urlhaus.abuse.ch/downloads/json_recent/"


@pytest.mark.asyncio
async def test_fetch_urlhaus_online_never_calls_json_recent():
    fixture = load_fixture("urlhaus_online.json")
    with respx.mock(assert_all_called=False) as mock:
        recent_route = mock.get(URLHAUS_RECENT_URL).mock(return_value=httpx.Response(200, json={}))
        mock.get(URLHAUS_ONLINE_URL).mock(return_value=httpx.Response(200, json=fixture))
        async with httpx.AsyncClient() as client:
            result = await fetch_urlhaus_online(client, URLHAUS_ONLINE_URL)

    assert recent_route.call_count == 0
    assert len(result) == 2
    assert result[0]["url"] == "http://evil.example/mal.exe"
    assert result[0]["host"] == "evil.example"


@pytest.mark.asyncio
async def test_fetch_urlhaus_online_strips_utc_suffix_so_pydantic_validates():
    fixture = load_fixture("urlhaus_online.json")
    with respx.mock() as mock:
        mock.get(URLHAUS_ONLINE_URL).mock(return_value=httpx.Response(200, json=fixture))
        async with httpx.AsyncClient() as client:
            result = await fetch_urlhaus_online(client, URLHAUS_ONLINE_URL)

    assert "UTC" not in result[0]["date_added"]
    # ne doit pas lever — la fixture porte "2026-06-01 10:00:00 UTC" (format réel abuse.ch)
    entry = UrlhausEntry.model_validate(result[0])
    assert entry.date_added.year == 2026
