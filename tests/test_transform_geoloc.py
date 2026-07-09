from datetime import UTC, datetime

import httpx
import pytest
import respx

from beesint_threat_report.transform import geoloc
from beesint_threat_report.transform.geoloc import enrich_ips_geoloc
from beesint_threat_report.validate.schemas import FeodoIpRecord

BATCH_URL = "http://ip-api.com/batch"


def _feodo(ip: str) -> FeodoIpRecord:
    return FeodoIpRecord(
        ip_address=ip,
        port=None,
        status="online",
        malware="Heodo",
        first_seen=datetime(2026, 5, 1, tzinfo=UTC),
        last_online=None,
        country=None,
        as_number=None,
        as_name=None,
    )


@pytest.mark.asyncio
async def test_enrich_ips_geoloc_omits_failed_status():
    records = [_feodo("203.0.113.10"), _feodo("198.51.100.20")]
    with respx.mock() as mock:
        mock.post(BATCH_URL).mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "status": "success",
                        "query": "203.0.113.10",
                        "lat": 1.0,
                        "lon": 2.0,
                        "country": "US",
                        "city": "NYC",
                        "isp": "Example",
                        "as": "AS1",
                    },
                    {"status": "fail", "query": "198.51.100.20", "message": "private range"},
                ],
            )
        )
        async with httpx.AsyncClient() as client:
            result = await enrich_ips_geoloc(client, records, BATCH_URL)

    assert set(result.keys()) == {"203.0.113.10"}
    assert result["203.0.113.10"]["country"] == "US"


@pytest.mark.asyncio
async def test_enrich_ips_geoloc_batches_over_100_ips(monkeypatch):
    async def _no_sleep(*_args, **_kwargs):
        return None

    monkeypatch.setattr(geoloc.asyncio, "sleep", _no_sleep)
    records = [_feodo(f"10.0.{i // 256}.{i % 256}") for i in range(150)]

    call_count = {"n": 0}

    def _responder(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        ips = request.content
        import json as _json

        queried = _json.loads(ips)
        return httpx.Response(200, json=[{"status": "success", "query": ip, "lat": 0, "lon": 0} for ip in queried])

    with respx.mock() as mock:
        mock.post(BATCH_URL).mock(side_effect=_responder)
        async with httpx.AsyncClient() as client:
            result = await enrich_ips_geoloc(client, records, BATCH_URL)

    assert call_count["n"] == 2
    assert len(result) == 150
