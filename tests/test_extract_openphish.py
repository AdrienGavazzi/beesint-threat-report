import httpx
import pytest
import respx

from beesint_threat_report.extract.openphish import fetch_openphish_feed

FEED_URL = "https://openphish.com/feed.txt"


@pytest.mark.asyncio
async def test_fetch_openphish_feed_parses_one_url_per_line():
    body = "http://evil.example/login\nhttp://other-evil.example/x\n"
    with respx.mock() as mock:
        mock.get(FEED_URL).mock(return_value=httpx.Response(200, text=body))
        async with httpx.AsyncClient() as client:
            result = await fetch_openphish_feed(client, FEED_URL)

    assert result == [{"url": "http://evil.example/login"}, {"url": "http://other-evil.example/x"}]


@pytest.mark.asyncio
async def test_fetch_openphish_feed_skips_blank_lines():
    body = "http://evil.example/login\n\n\nhttp://other-evil.example/x\n"
    with respx.mock() as mock:
        mock.get(FEED_URL).mock(return_value=httpx.Response(200, text=body))
        async with httpx.AsyncClient() as client:
            result = await fetch_openphish_feed(client, FEED_URL)

    assert len(result) == 2
