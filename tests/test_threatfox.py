from datetime import UTC, datetime

import httpx
import pandera.errors
import polars as pl
import pytest
import respx
from conftest import load_fixture

from beesint_threat_report import orchestrate
from beesint_threat_report.config import Settings
from beesint_threat_report.extract.threatfox import ThreatFoxAuthError, fetch_threatfox
from beesint_threat_report.transform.kpis import compute_kpis
from beesint_threat_report.transform.threatfox import merge_threatfox_ip_iocs
from beesint_threat_report.validate.frames import validate_ip_threat_frame
from beesint_threat_report.validate.schemas import ThreatFoxIoc

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"


def _utc(*args) -> datetime:
    return datetime(*args, tzinfo=UTC)


def _ioc(
    ioc_id="1",
    ioc_type="ip:port",
    ioc_value="203.0.113.10:443",
    malware_printable="Heodo",
    first_seen=None,
    last_seen=None,
) -> ThreatFoxIoc:
    return ThreatFoxIoc(
        ioc_id=ioc_id,
        ioc_type=ioc_type,
        ioc_value=ioc_value,
        threat_type="botnet_cc",
        malware="win.heodo",
        malware_printable=malware_printable,
        confidence_level=90,
        first_seen=first_seen or _utc(2026, 6, 1),
        last_seen=last_seen,
        reporter="abuse_ch",
        tags=[],
    )


# ---- extract/threatfox.py ----------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_threatfox_success_single_post_with_auth_key_header():
    fixture = load_fixture("threatfox_get_iocs.json")
    with respx.mock() as mock:
        route = mock.post(THREATFOX_URL).mock(return_value=httpx.Response(200, json=fixture))
        async with httpx.AsyncClient() as client:
            result = await fetch_threatfox(client, "secret-key", days=7, base_url=THREATFOX_URL)

    assert route.call_count == 1
    assert route.calls[0].request.headers["Auth-Key"] == "secret-key"
    assert len(result) == 4
    ip_result = next(r for r in result if r["ioc_type"] == "ip:port")
    assert ip_result["ioc_value"] == "203.0.113.10:443"
    assert ip_result["malware_printable"] == "Heodo"
    assert ip_result["first_seen"] == "2026-06-01 10:00:00"  # suffixe " UTC" retiré


@pytest.mark.asyncio
async def test_fetch_threatfox_401_raises_auth_error_no_retry():
    with respx.mock() as mock:
        route = mock.post(THREATFOX_URL).mock(return_value=httpx.Response(401, json={"error": "Unauthorized"}))
        async with httpx.AsyncClient() as client:
            with pytest.raises(ThreatFoxAuthError):
                await fetch_threatfox(client, "bad-key", days=7, base_url=THREATFOX_URL)

    assert route.call_count == 1


@pytest.mark.asyncio
async def test_fetch_threatfox_429_then_success_retries():
    fixture = load_fixture("threatfox_get_iocs.json")
    with respx.mock() as mock:
        route = mock.post(THREATFOX_URL)
        route.side_effect = [httpx.Response(429), httpx.Response(200, json=fixture)]
        async with httpx.AsyncClient() as client:
            result = await fetch_threatfox(client, "secret-key", days=7, base_url=THREATFOX_URL)

    assert route.call_count == 2
    assert len(result) == 4


@pytest.mark.asyncio
async def test_fetch_threatfox_no_result_status_returns_empty_list():
    with respx.mock() as mock:
        mock.post(THREATFOX_URL).mock(return_value=httpx.Response(200, json={"query_status": "no_result", "data": []}))
        async with httpx.AsyncClient() as client:
            result = await fetch_threatfox(client, "secret-key", days=7, base_url=THREATFOX_URL)

    assert result == []


# ---- orchestrate: dégradation clé absente/invalide -----------------------------------


@pytest.mark.asyncio
async def test_run_threatfox_source_success_returns_validated_threatfox_ioc_objects(tmp_path):
    fixture = load_fixture("threatfox_get_iocs.json")
    settings = Settings(threatfox_auth_key="secret-key", cache_dir=tmp_path / ".cache", force_refresh=True)
    with respx.mock() as mock:
        route = mock.post(THREATFOX_URL).mock(return_value=httpx.Response(200, json=fixture))
        async with httpx.AsyncClient() as client:
            iocs, status = await orchestrate._run_threatfox_source(
                client, settings, "run-1", datetime.now(UTC), str(tmp_path), None
            )
    assert route.call_count == 1
    assert status == "ok"
    assert len(iocs) == 4
    assert all(isinstance(ioc, ThreatFoxIoc) for ioc in iocs)


@pytest.mark.asyncio
async def test_run_threatfox_source_skips_before_network_call_when_key_absent(tmp_path):
    settings = Settings(threatfox_auth_key=None, cache_dir=tmp_path / ".cache")
    async with httpx.AsyncClient() as client:
        iocs, status = await orchestrate._run_threatfox_source(
            client, settings, "run-1", datetime.now(UTC), str(tmp_path), None
        )
    assert iocs == []
    assert status == "skipped:no_auth_key"


@pytest.mark.asyncio
async def test_run_threatfox_source_invalid_key_marks_skipped(tmp_path):
    settings = Settings(threatfox_auth_key="bad-key", cache_dir=tmp_path / ".cache", force_refresh=True)
    with respx.mock() as mock:
        mock.post(THREATFOX_URL).mock(return_value=httpx.Response(403, json={"error": "Unauthorized"}))
        async with httpx.AsyncClient() as client:
            iocs, status = await orchestrate._run_threatfox_source(
                client, settings, "run-1", datetime.now(UTC), str(tmp_path), None
            )
    assert iocs == []
    assert status == "skipped:invalid_auth_key"


# ---- transform/threatfox.py: merge_threatfox_ip_iocs ----------------------------------


def _base_ip_frame() -> pl.DataFrame:
    return pl.DataFrame(
        {
            "ip_address": ["1.1.1.1", "2.2.2.2", "3.3.3.3"],
            "status": ["online", "online", "offline"],
            "malware": ["Heodo", "Dridex", "QakBot"],
            "first_seen": [_utc(2026, 5, 1), _utc(2026, 5, 2), _utc(2026, 5, 3)],
            "last_online": [None, None, None],
            "country": ["US", "DE", "FR"],
            "is_new": pl.Series([False, False, False], dtype=pl.Boolean),
            "source": ["feodo", "urlhaus", "both"],
        }
    )


def test_merge_threatfox_ip_iocs_four_source_combinations():
    ip_frame = _base_ip_frame()
    threatfox_iocs = [
        _ioc(ioc_id="1", ioc_value="1.1.1.1:443"),  # déjà feodo -> feodo+threatfox
        _ioc(ioc_id="2", ioc_value="2.2.2.2:8080"),  # déjà urlhaus -> urlhaus+threatfox
        _ioc(ioc_id="3", ioc_value="3.3.3.3:22"),  # déjà both -> both+threatfox
        _ioc(ioc_id="4", ioc_value="4.4.4.4:9001"),  # absente -> nouvelle ligne "threatfox"
        _ioc(ioc_id="5", ioc_type="domain", ioc_value="not-an-ip.example"),  # ignoré (pas ip:port)
    ]

    result = merge_threatfox_ip_iocs(ip_frame, threatfox_iocs)

    by_ip = {row["ip_address"]: row["source"] for row in result.to_dicts()}
    assert by_ip["1.1.1.1"] == "feodo+threatfox"
    assert by_ip["2.2.2.2"] == "urlhaus+threatfox"
    assert by_ip["3.3.3.3"] == "both+threatfox"
    assert by_ip["4.4.4.4"] == "threatfox"
    assert result.height == 4  # pas de doublon, le domain n'a pas créé de ligne


def test_merge_threatfox_ip_iocs_no_ip_type_iocs_returns_unchanged_with_source():
    ip_frame = pl.DataFrame(
        {
            "ip_address": ["1.1.1.1"],
            "status": ["online"],
            "malware": ["Heodo"],
            "first_seen": [_utc(2026, 5, 1)],
            "last_online": [None],
            "country": ["US"],
            "is_new": pl.Series([False], dtype=pl.Boolean),
        }
    )
    result = merge_threatfox_ip_iocs(ip_frame, [_ioc(ioc_type="domain", ioc_value="x.example")])
    assert result.height == 1
    assert result["source"].to_list() == ["feodo"]


def test_merge_threatfox_ip_iocs_empty_ip_frame_cold_start():
    empty = pl.DataFrame(
        schema={
            "ip_address": pl.Utf8,
            "status": pl.Utf8,
            "malware": pl.Utf8,
            "first_seen": pl.Datetime,
            "last_online": pl.Datetime,
            "country": pl.Utf8,
        }
    )
    result = merge_threatfox_ip_iocs(empty, [_ioc(ioc_value="9.9.9.9:443")])
    assert result.height == 1
    assert result["source"].to_list() == ["threatfox"]


# ---- validate/frames.py: IpThreatFrameSchema (7 catégories) ---------------------------


def test_validate_ip_threat_frame_all_seven_source_categories_pass():
    df = pl.DataFrame(
        {
            "ip_address": [f"10.0.0.{i}" for i in range(7)],
            "status": ["online"] * 7,
            "first_seen": [_utc(2026, 5, 1)] * 7,
            "is_new": pl.Series([None] * 7, dtype=pl.Boolean),
            "source": [
                "feodo",
                "urlhaus",
                "both",
                "threatfox",
                "feodo+threatfox",
                "urlhaus+threatfox",
                "both+threatfox",
            ],
        }
    )
    result = validate_ip_threat_frame(df)
    assert result.height == 7


def test_validate_ip_threat_frame_unknown_source_category_rejected():
    df = pl.DataFrame(
        {
            "ip_address": ["10.0.0.1"],
            "status": ["online"],
            "first_seen": [_utc(2026, 5, 1)],
            "is_new": pl.Series([None], dtype=pl.Boolean),
            "source": ["not-a-real-source"],
        }
    )
    with pytest.raises(pandera.errors.SchemaErrors):
        validate_ip_threat_frame(df)


# ---- transform/kpis.py: familles de malware ThreatFox ----------------------------------


def _empty_frames():
    cve_df = pl.DataFrame({"cve_id": [], "vendor": [], "cwe_ids": []})
    kev_df = pl.DataFrame({"cve_id": [], "due_date": [], "known_ransomware_campaign_use": []})
    feodo_df = pl.DataFrame({"ip_address": [], "status": [], "country": []})
    urlhaus_df = pl.DataFrame({"url": [], "url_status": []})
    return cve_df, kev_df, feodo_df, urlhaus_df


def test_compute_kpis_threatfox_malware_families_count_domain_and_hash_only():
    cve_df, kev_df, feodo_df, urlhaus_df = _empty_frames()
    threatfox_iocs = [
        _ioc(ioc_id="1", ioc_type="ip:port", ioc_value="1.1.1.1:443", malware_printable="Heodo"),
        _ioc(ioc_id="2", ioc_type="domain", ioc_value="a.example", malware_printable="TrickBot"),
        _ioc(ioc_id="3", ioc_type="md5_hash", ioc_value="aa" * 16, malware_printable="Dridex"),
        _ioc(ioc_id="4", ioc_type="sha256_hash", ioc_value="bb" * 32, malware_printable="TrickBot"),
    ]
    kpis = compute_kpis(
        cve_df, kev_df, feodo_df, urlhaus_df, mean_time_to_kev=None, previous_kpis=None, threatfox_iocs=threatfox_iocs
    )
    # TrickBot + Dridex = 2 familles distinctes ; Heodo (ip:port) exclu du comptage
    assert kpis.threatfox_malware_families_count == 2
    assert kpis.threatfox_malware_families_trend_pct is None  # cold start


def test_compute_kpis_threatfox_malware_families_trend_vs_previous():
    from beesint_threat_report.transform.kpis import ReportKpis

    cve_df, kev_df, feodo_df, urlhaus_df = _empty_frames()
    previous = ReportKpis(
        cve_critical_count=0,
        cve_critical_trend_pct=None,
        cve_high_count=0,
        kev_new_count=0,
        kev_urgent_count=0,
        kev_ransomware_count=0,
        mean_time_to_kev_days=None,
        c2_active_count=0,
        malicious_url_count=0,
        top_countries=[],
        top_vendors=[],
        cwe_distribution=[],
        threatfox_malware_families_count=1,
    )
    threatfox_iocs = [
        _ioc(ioc_id="1", ioc_type="domain", ioc_value="a.example", malware_printable="TrickBot"),
        _ioc(ioc_id="2", ioc_type="domain", ioc_value="b.example", malware_printable="Dridex"),
    ]
    kpis = compute_kpis(cve_df, kev_df, feodo_df, urlhaus_df, None, previous, threatfox_iocs=threatfox_iocs)
    assert kpis.threatfox_malware_families_count == 2
    assert kpis.threatfox_malware_families_trend_pct == 100.0
