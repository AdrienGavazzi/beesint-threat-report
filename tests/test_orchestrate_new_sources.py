from datetime import datetime

import httpx
import polars as pl
import pytest
import respx

from beesint_threat_report import orchestrate
from beesint_threat_report.config import Settings

SHODAN_URL = "https://internetdb.shodan.io"
GREYNOISE_URL = "https://api.greynoise.io/v3/community"
EPSS_URL = "https://api.first.org/data/v1/epss"


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


@pytest.mark.asyncio
async def test_run_epss_source_skips_when_no_cve_ids(tmp_path):
    settings = Settings(cache_dir=tmp_path / ".cache")
    async with httpx.AsyncClient() as client:
        data, status = await orchestrate._run_epss_source(client, settings, "run-1", [], str(tmp_path), None)
    assert data == {}
    assert status == "skipped:no_cve_this_run"


@pytest.mark.asyncio
async def test_run_epss_source_success_returns_cve_keyed_dict(tmp_path):
    settings = Settings(cache_dir=tmp_path / ".cache", force_refresh=True)
    with respx.mock() as mock:
        mock.get(EPSS_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": [{"cve": "CVE-2021-44228", "epss": "0.999990000", "percentile": "1.000000000", "date": "d"}]
                },
            )
        )
        async with httpx.AsyncClient() as client:
            data, status = await orchestrate._run_epss_source(
                client, settings, "run-1", ["CVE-2021-44228"], str(tmp_path), None
            )
    assert status == "ok"
    assert data == {"CVE-2021-44228": {"epss_score": 0.99999, "epss_percentile": 1.0}}


# ---- _build_top_cves: merge EPSS dans le top-N ------------------------------------------------


def _ranked_cve_frame() -> pl.DataFrame:
    return pl.DataFrame(
        {
            "cve_id": ["CVE-2021-44228", "CVE-2024-3400"],
            "description": ["Log4Shell", "PAN-OS RCE"],
            "cvss_v3_score": [10.0, 9.3],
            "cvss_v3_severity": ["CRITICAL", "CRITICAL"],
            "vendor": ["Apache", "Palo Alto"],
            "cwe_ids": [["CWE-502"], ["CWE-78"]],
            "published_date": [datetime(2021, 12, 10), datetime(2024, 4, 12)],
        }
    )


def _empty_kev_frame() -> pl.DataFrame:
    return pl.DataFrame({"cve_id": [], "date_added": [], "known_ransomware_campaign_use": []})


def test_build_top_cves_merges_epss_scores():
    epss_by_id = {"CVE-2021-44228": {"epss_score": 0.99999, "epss_percentile": 1.0}}
    result = orchestrate._build_top_cves(_ranked_cve_frame(), _empty_kev_frame(), epss_by_id)
    by_id = {r["cve_id"]: r for r in result}
    assert by_id["CVE-2021-44228"]["epss_score"] == 0.99999
    assert by_id["CVE-2021-44228"]["epss_percentile"] == 1.0
    assert by_id["CVE-2024-3400"]["epss_score"] is None


def test_build_top_cves_defaults_epss_to_none_when_not_passed():
    result = orchestrate._build_top_cves(_ranked_cve_frame(), _empty_kev_frame())
    assert result[0]["epss_score"] is None
    assert result[0]["epss_percentile"] is None


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

    # "Heodo" est l'alias historique FeodoTracker d'Emotet — vérifie que l'alias résout bien
    # vers les mêmes techniques que "emotet" dans mitre_attack_map.py.
    assert by_ip["1.1.1.1"]["mitre_techniques"] == ["T1071.001", "T1105", "T1204.002"]
    assert by_ip["2.2.2.2"]["mitre_techniques"] == ["T1071.001", "T1204.002"]


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
    assert result[0]["mitre_techniques"] == ["T1071.001", "T1105", "T1204.002"]
    assert result[0]["shodan_has_data"] is False
    assert result[0]["confirmed_by_spamhaus"] is False
    assert result[0]["greynoise_classification"] is None
