import httpx
import pytest
import respx
from conftest import load_fixture

from beesint_threat_report.extract.feodo import fetch_feodo_snapshot

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


@pytest.mark.asyncio
async def test_fetch_feodo_snapshot_maps_fields_to_pydantic_names():
    fixture = load_fixture("feodo_ipblocklist.json")
    with respx.mock() as mock:
        mock.get(FEODO_URL).mock(return_value=httpx.Response(200, json=fixture))
        async with httpx.AsyncClient() as client:
            result = await fetch_feodo_snapshot(client, FEODO_URL)

    assert len(result) == 2
    assert result[0]["ip_address"] == "203.0.113.10"
    assert result[0]["malware"] == "Heodo"
    assert result[0]["status"] == "online"
    assert result[1]["last_online"] is None
