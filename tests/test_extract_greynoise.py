import httpx
import pytest
import respx

from beesint_threat_report.extract.greynoise import fetch_greynoise_classifications

BASE_URL = "https://api.greynoise.io/v3/community"


@pytest.mark.asyncio
async def test_fetch_greynoise_keeps_raw_classification_value():
    with respx.mock() as mock:
        route = mock.get(f"{BASE_URL}/1.1.1.1").mock(
            return_value=httpx.Response(200, json={"ip": "1.1.1.1", "classification": "benign"})
        )
        async with httpx.AsyncClient() as client:
            result = await fetch_greynoise_classifications(client, ["1.1.1.1"], api_key="key", base_url=BASE_URL)

    # jamais de remap "benign"->"scanner" (cf. commentaire extract/greynoise.py) — valeur brute
    assert result == [{"ip": "1.1.1.1", "classification": "benign"}]
    assert route.calls[0].request.headers["key"] == "key"


@pytest.mark.asyncio
async def test_fetch_greynoise_404_treated_as_no_data():
    with respx.mock() as mock:
        mock.get(f"{BASE_URL}/9.9.9.9").mock(return_value=httpx.Response(404))
        async with httpx.AsyncClient() as client:
            result = await fetch_greynoise_classifications(client, ["9.9.9.9"], api_key="key", base_url=BASE_URL)

    assert result == []


@pytest.mark.asyncio
async def test_fetch_greynoise_429_stops_remaining_ips_without_raising():
    # assert_all_called=False : la route "2.2.2.2" est volontairement enregistrée mais jamais
    # appelée — c'est exactement le comportement attendu (arrêt au 1er 429, cf. concurrency=1
    # pour un ordre d'appel déterministe), pas une erreur de mock.
    with respx.mock(assert_all_called=False) as mock:
        mock.get(f"{BASE_URL}/1.1.1.1").mock(return_value=httpx.Response(429))
        mock.get(f"{BASE_URL}/2.2.2.2").mock(return_value=httpx.Response(429))
        async with httpx.AsyncClient() as client:
            result = await fetch_greynoise_classifications(
                client, ["1.1.1.1", "2.2.2.2"], api_key="key", base_url=BASE_URL, concurrency=1
            )

    assert result == []  # dégradation propre, jamais d'exception qui remonte à l'appelant


@pytest.mark.asyncio
async def test_fetch_greynoise_malicious_classification_passthrough():
    with respx.mock() as mock:
        mock.get(f"{BASE_URL}/6.6.6.6").mock(
            return_value=httpx.Response(200, json={"ip": "6.6.6.6", "classification": "malicious"})
        )
        async with httpx.AsyncClient() as client:
            result = await fetch_greynoise_classifications(client, ["6.6.6.6"], api_key="key", base_url=BASE_URL)

    assert result == [{"ip": "6.6.6.6", "classification": "malicious"}]
