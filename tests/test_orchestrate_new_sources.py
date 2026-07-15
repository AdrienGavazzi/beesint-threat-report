from datetime import UTC, datetime

import httpx
import polars as pl
import pytest
import respx

from beesint_threat_report import orchestrate
from beesint_threat_report.config import Settings

SHODAN_URL = "https://internetdb.shodan.io"
GREYNOISE_URL = "https://api.greynoise.io/v3/community"


# ---- skip-before-network-call when prerequisites are missing -------------------------------


@pytest.mark.asyncio
async def test_run_greynoise_source_skips_before_network_call_when_key_absent(tmp_path):
    settings = Settings(greynoise_api_key=None, cache_dir=tmp_path / ".cache")
    async with httpx.AsyncClient() as client:
        data, status = await orchestrate._run_greynoise_source(
            client, settings, "run-1", ["1.1.1.1"], str(tmp_path), None
        )
    assert data == {}
    assert status == "skipped:no_api_key"


@pytest.mark.asyncio
async def test_run_greynoise_source_skips_when_no_ips(tmp_path):
    settings = Settings(greynoise_api_key="key", cache_dir=tmp_path / ".cache")
    async with httpx.AsyncClient() as client:
        data, status = await orchestrate._run_greynoise_source(client, settings, "run-1", [], str(tmp_path), None)
    assert data == {}
    assert status == "skipped:no_c2_ips"


@pytest.mark.asyncio
async def test_run_phishtank_source_skips_before_network_call_when_key_absent(tmp_path):
    settings = Settings(phishtank_api_key=None, cache_dir=tmp_path / ".cache")
    async with httpx.AsyncClient() as client:
        entries, status = await orchestrate._run_phishtank_source(
            client, settings, "run-1", datetime.now(UTC), str(tmp_path), None
        )
    assert entries == []
    assert status == "skipped:no_api_key"


@pytest.mark.asyncio
async def test_run_shodan_source_skips_when_no_ips(tmp_path):
    settings = Settings(cache_dir=tmp_path / ".cache")
    async with httpx.AsyncClient() as client:
        data, status = await orchestrate._run_shodan_source(client, settings, "run-1", [], str(tmp_path), None)
    assert data == {}
    assert status == "skipped:no_c2_ips"


@pytest.mark.asyncio
async def test_run_spamhaus_source_skips_when_no_ips(tmp_path):
    settings = Settings(cache_dir=tmp_path / ".cache")
    async with httpx.AsyncClient() as client:
        confirmed, status = await orchestrate._run_spamhaus_source(client, settings, "run-1", [], str(tmp_path), None)
    assert confirmed == set()
    assert status == "skipped:no_c2_ips"


# ---- happy paths (mocked network) -----------------------------------------------------------


@pytest.mark.asyncio
async def test_run_shodan_source_success_returns_ip_keyed_dict(tmp_path):
    settings = Settings(cache_dir=tmp_path / ".cache", force_refresh=True)
    with respx.mock() as mock:
        mock.get(f"{SHODAN_URL}/1.1.1.1").mock(
            return_value=httpx.Response(
                200, json={"ip": "1.1.1.1", "ports": [443], "vulns": ["CVE-2024-0001"], "tags": []}
            )
        )
        async with httpx.AsyncClient() as client:
            data, status = await orchestrate._run_shodan_source(
                client, settings, "run-1", ["1.1.1.1"], str(tmp_path), None
            )
    assert status == "ok"
    assert data == {"1.1.1.1": {"ports": [443], "vulns": ["CVE-2024-0001"]}}


@pytest.mark.asyncio
async def test_run_greynoise_source_success_returns_ip_keyed_dict(tmp_path):
    settings = Settings(greynoise_api_key="key", cache_dir=tmp_path / ".cache", force_refresh=True)
    with respx.mock() as mock:
        mock.get(f"{GREYNOISE_URL}/1.1.1.1").mock(
            return_value=httpx.Response(200, json={"ip": "1.1.1.1", "classification": "malicious"})
        )
        async with httpx.AsyncClient() as client:
            data, status = await orchestrate._run_greynoise_source(
                client, settings, "run-1", ["1.1.1.1"], str(tmp_path), None
            )
    assert status == "ok"
    assert data == {"1.1.1.1": "malicious"}


# ---- _build_top_ips: merge des 3 nouvelles sources dans le top-N -----------------------------


def _ranked_ip_frame() -> pl.DataFrame:
    return pl.DataFrame(
        {
            "ip_address": ["1.1.1.1", "2.2.2.2"],
            "malware": ["Heodo", "Dridex"],
            "source": ["feodo", "feodo"],
            "first_seen": [datetime(2026, 7, 1), datetime(2026, 7, 2)],
            "last_online": [None, None],
            "country": ["US", "DE"],
        }
    )


def test_build_top_ips_merges_shodan_spamhaus_greynoise():
    shodan = {"1.1.1.1": {"ports": [22, 443], "vulns": ["CVE-2024-0001"]}}
    spamhaus_confirmed = {"1.1.1.1"}
    greynoise_data = {"2.2.2.2": "malicious"}

    result = orchestrate._build_top_ips(
        _ranked_ip_frame(),
        geo={},
        shodan=shodan,
        spamhaus_confirmed=spamhaus_confirmed,
        greynoise_classifications=greynoise_data,
    )

    by_ip = {r["ip"]: r for r in result}
    assert by_ip["1.1.1.1"]["open_ports"] == [22, 443]
    assert by_ip["1.1.1.1"]["known_cves"] == ["CVE-2024-0001"]
    assert by_ip["1.1.1.1"]["shodan_has_data"] is True
    assert by_ip["1.1.1.1"]["confirmed_by_spamhaus"] is True
    assert by_ip["1.1.1.1"]["greynoise_classification"] is None

    assert by_ip["2.2.2.2"]["shodan_has_data"] is False
    assert by_ip["2.2.2.2"]["confirmed_by_spamhaus"] is False
    assert by_ip["2.2.2.2"]["greynoise_classification"] == "malicious"


def test_build_top_ips_defaults_when_no_enrichment_passed():
    ranked = pl.DataFrame(
        {
            "ip_address": ["1.1.1.1"],
            "malware": ["Heodo"],
            "source": ["feodo"],
            "first_seen": [datetime(2026, 7, 1)],
            "last_online": [None],
            "country": ["US"],
        }
    )
    result = orchestrate._build_top_ips(ranked, geo={})
    assert result[0]["open_ports"] == []
    assert result[0]["known_cves"] == []
    assert result[0]["shodan_has_data"] is False
    assert result[0]["confirmed_by_spamhaus"] is False
    assert result[0]["greynoise_classification"] is None
