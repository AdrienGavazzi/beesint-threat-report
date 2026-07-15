import httpx
import pytest
import respx

from beesint_threat_report.extract.shodan_internetdb import fetch_internetdb_for_ips

BASE_URL = "https://internetdb.shodan.io"


@pytest.mark.asyncio
async def test_fetch_internetdb_maps_fields_for_indexed_ip():
    with respx.mock() as mock:
        mock.get(f"{BASE_URL}/1.1.1.1").mock(
            return_value=httpx.Response(
                200, json={"ip": "1.1.1.1", "ports": [53, 443], "vulns": ["CVE-2024-0001"], "tags": ["cdn"]}
            )
        )
        async with httpx.AsyncClient() as client:
            result = await fetch_internetdb_for_ips(client, ["1.1.1.1"], base_url=BASE_URL)

    assert result == [{"ip": "1.1.1.1", "ports": [53, 443], "vulns": ["CVE-2024-0001"], "tags": ["cdn"]}]


@pytest.mark.asyncio
async def test_fetch_internetdb_404_treated_as_no_data_not_error():
    with respx.mock() as mock:
        mock.get(f"{BASE_URL}/203.0.113.5").mock(return_value=httpx.Response(404))
        async with httpx.AsyncClient() as client:
            result = await fetch_internetdb_for_ips(client, ["203.0.113.5"], base_url=BASE_URL)

    assert result == []


@pytest.mark.asyncio
async def test_fetch_internetdb_one_ip_per_call_mixed_hit_and_miss():
    with respx.mock() as mock:
        mock.get(f"{BASE_URL}/1.1.1.1").mock(
            return_value=httpx.Response(200, json={"ip": "1.1.1.1", "ports": [443], "vulns": [], "tags": []})
        )
        mock.get(f"{BASE_URL}/9.9.9.9").mock(return_value=httpx.Response(404))
        async with httpx.AsyncClient() as client:
            result = await fetch_internetdb_for_ips(client, ["1.1.1.1", "9.9.9.9"], base_url=BASE_URL, concurrency=2)

    assert len(result) == 1
    assert result[0]["ip"] == "1.1.1.1"


@pytest.mark.asyncio
async def test_fetch_internetdb_transport_error_on_one_ip_does_not_abort_others():
    with respx.mock() as mock:
        mock.get(f"{BASE_URL}/1.1.1.1").mock(side_effect=httpx.ConnectError("boom"))
        mock.get(f"{BASE_URL}/2.2.2.2").mock(
            return_value=httpx.Response(200, json={"ip": "2.2.2.2", "ports": [22], "vulns": [], "tags": []})
        )
        async with httpx.AsyncClient() as client:
            result = await fetch_internetdb_for_ips(client, ["1.1.1.1", "2.2.2.2"], base_url=BASE_URL)

    assert len(result) == 1
    assert result[0]["ip"] == "2.2.2.2"


# ---- test réseau réel (pas de clé requise) — se skip proprement si le sandbox n'a pas de réseau
# sortant, ne fait jamais échouer la suite (CDC : "try, but don't fail the task if outbound
# network calls aren't permitted") ----------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_internetdb_real_network_call_8_8_8_8():
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            result = await fetch_internetdb_for_ips(client, ["8.8.8.8"])
    except Exception as exc:  # pragma: no cover - dépend de l'environnement réseau du sandbox
        pytest.skip(f"pas d'accès réseau sortant dans ce sandbox: {exc}")

    if not result:
        pytest.skip("8.8.8.8 non indexée par Shodan InternetDB au moment du test")
    assert result[0]["ip"] == "8.8.8.8"
    assert isinstance(result[0]["ports"], list)
