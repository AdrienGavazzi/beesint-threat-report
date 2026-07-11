import httpx
import pytest
import respx

from beesint_threat_report.publish.webhook import publish_status

WEBHOOK_URL = "https://backend.example.com/internal/threat-report/status"


@pytest.mark.asyncio
async def test_publish_status_dry_run_when_url_none():
    async with httpx.AsyncClient() as client:
        with respx.mock(assert_all_called=False) as mock:
            route = mock.post(WEBHOOK_URL)
            status = await publish_status(client, None, "secret", {"run_id": "r1"})
    assert status == "dry_run"
    assert route.call_count == 0


@pytest.mark.asyncio
async def test_publish_status_sent_on_200():
    with respx.mock() as mock:
        mock.post(WEBHOOK_URL).mock(return_value=httpx.Response(200))
        async with httpx.AsyncClient() as client:
            status = await publish_status(client, WEBHOOK_URL, "secret", {"run_id": "r1"})
    assert status == "sent"


@pytest.mark.asyncio
async def test_publish_status_failed_after_persistent_500_never_raises():
    with respx.mock() as mock:
        mock.post(WEBHOOK_URL).mock(return_value=httpx.Response(500))
        async with httpx.AsyncClient() as client:
            status = await publish_status(client, WEBHOOK_URL, "secret", {"run_id": "r1"})
    assert status == "failed:500"
