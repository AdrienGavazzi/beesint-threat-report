import httpx
import pytest
import respx

from beesint_threat_report.extract.breachdirectory import check_breachdirectory

URL = "https://breachdirectory.p.rapidapi.com/"


@pytest.mark.asyncio
async def test_check_breachdirectory_returns_found_count_when_int():
    with respx.mock() as mock:
        mock.get(URL).mock(return_value=httpx.Response(200, json={"success": True, "found": 3}))
        async with httpx.AsyncClient() as client:
            result = await check_breachdirectory(client, "example.com", "test-key")
    assert result == 3


@pytest.mark.asyncio
async def test_check_breachdirectory_falls_back_to_result_list_length():
    with respx.mock() as mock:
        mock.get(URL).mock(return_value=httpx.Response(200, json={"success": True, "result": [{"a": 1}, {"b": 2}]}))
        async with httpx.AsyncClient() as client:
            result = await check_breachdirectory(client, "example.com", "test-key")
    assert result == 2


@pytest.mark.asyncio
async def test_check_breachdirectory_returns_zero_when_not_success():
    with respx.mock() as mock:
        mock.get(URL).mock(return_value=httpx.Response(200, json={"success": False}))
        async with httpx.AsyncClient() as client:
            result = await check_breachdirectory(client, "example.com", "test-key")
    assert result == 0


@pytest.mark.asyncio
async def test_check_breachdirectory_returns_zero_on_404():
    with respx.mock() as mock:
        mock.get(URL).mock(return_value=httpx.Response(404))
        async with httpx.AsyncClient() as client:
            result = await check_breachdirectory(client, "example.com", "test-key")
    assert result == 0


@pytest.mark.asyncio
async def test_check_breachdirectory_never_raises_on_network_error():
    with respx.mock() as mock:
        mock.get(URL).mock(side_effect=httpx.ConnectError("network down"))
        async with httpx.AsyncClient() as client:
            result = await check_breachdirectory(client, "example.com", "test-key")
    assert result == 0
