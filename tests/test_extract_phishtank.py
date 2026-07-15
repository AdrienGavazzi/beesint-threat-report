import bz2
import json

import httpx
import pytest
import respx

from beesint_threat_report.extract.phishtank import fetch_phishtank_feed

BASE_URL = "http://data.phishtank.com/data"
API_KEY = "test-key"
FEED_URL = f"{BASE_URL}/{API_KEY}/online-valid.json.bz2"

_RAW_FEED = [
    {
        "phish_id": 12345,
        "url": "http://evil.example/login",
        "phish_detail_url": "http://phishtank.com/phish_detail.php?phish_id=12345",
        "submission_time": "2026-07-10T10:00:00+00:00",
        "verified": "yes",
        "verification_time": "2026-07-10T10:05:00+00:00",
        "online": "yes",
        "target": "Example Bank",
    }
]


@pytest.mark.asyncio
async def test_fetch_phishtank_feed_decompresses_bz2_and_maps_fields():
    compressed = bz2.compress(json.dumps(_RAW_FEED).encode())
    with respx.mock() as mock:
        mock.get(FEED_URL).mock(return_value=httpx.Response(200, content=compressed))
        async with httpx.AsyncClient() as client:
            result = await fetch_phishtank_feed(client, API_KEY, base_url=BASE_URL)

    assert result == [
        {
            "phish_id": "12345",
            "url": "http://evil.example/login",
            "submission_time": "2026-07-10T10:00:00+00:00",
            "verified": True,
            "online": True,
            "target": "Example Bank",
        }
    ]


@pytest.mark.asyncio
async def test_fetch_phishtank_feed_not_verified_or_offline_maps_false():
    raw = [{**_RAW_FEED[0], "verified": "no", "online": "no", "target": ""}]
    compressed = bz2.compress(json.dumps(raw).encode())
    with respx.mock() as mock:
        mock.get(FEED_URL).mock(return_value=httpx.Response(200, content=compressed))
        async with httpx.AsyncClient() as client:
            result = await fetch_phishtank_feed(client, API_KEY, base_url=BASE_URL)

    assert result[0]["verified"] is False
    assert result[0]["online"] is False
    assert result[0]["target"] == ""
