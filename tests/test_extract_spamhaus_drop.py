import httpx
import pytest
import respx

from beesint_threat_report.extract.spamhaus_drop import (
    fetch_spamhaus_ranges,
    match_ips_against_ranges,
)

DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
EDROP_URL = "https://www.spamhaus.org/drop/edrop.txt"

_DROP_SAMPLE = """; Spamhaus DROP List
; https://www.spamhaus.org/drop/drop.txt
1.10.16.0/20 ; SBL256894
2.2.2.0/24 ; SBL999999
"""
_EDROP_SAMPLE = """; Spamhaus EDROP List
# alt comment style
5.5.5.0/24 ; SBL111111
"""


@pytest.mark.asyncio
async def test_fetch_spamhaus_ranges_parses_both_lists_skips_comments():
    with respx.mock() as mock:
        mock.get(DROP_URL).mock(return_value=httpx.Response(200, text=_DROP_SAMPLE))
        mock.get(EDROP_URL).mock(return_value=httpx.Response(200, text=_EDROP_SAMPLE))
        async with httpx.AsyncClient() as client:
            result = await fetch_spamhaus_ranges(client, DROP_URL, EDROP_URL)

    assert result == [
        {"cidr": "1.10.16.0/20"},
        {"cidr": "2.2.2.0/24"},
        {"cidr": "5.5.5.0/24"},
    ]


def test_match_ips_against_ranges_finds_ip_inside_cidr():
    ranges = ["1.10.16.0/20", "5.5.5.0/24"]
    ips = ["1.10.20.5", "8.8.8.8", "5.5.5.100"]
    matched = match_ips_against_ranges(ips, ranges)
    assert matched == {"1.10.20.5", "5.5.5.100"}


def test_match_ips_against_ranges_ignores_malformed_cidr_and_ip():
    matched = match_ips_against_ranges(["not-an-ip", "1.1.1.1"], ["also-not-a-cidr", "1.1.1.0/24"])
    assert matched == {"1.1.1.1"}


def test_match_ips_against_ranges_empty_ranges_returns_empty_set():
    assert match_ips_against_ranges(["1.1.1.1"], []) == set()


# ---- test réseau réel (pas de clé requise) --------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_spamhaus_ranges_real_network_call():
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            ranges = await fetch_spamhaus_ranges(client)
    except Exception as exc:  # pragma: no cover - dépend de l'environnement réseau du sandbox
        pytest.skip(f"pas d'accès réseau sortant dans ce sandbox: {exc}")

    assert len(ranges) > 100  # DROP+EDROP combinés font toujours plusieurs milliers de lignes
    assert all("cidr" in r for r in ranges)
