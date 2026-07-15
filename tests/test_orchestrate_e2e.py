from datetime import UTC, datetime, timedelta

import boto3
import httpx
import pytest
import respx
from conftest import load_fixture
from moto.server import ThreadedMotoServer

from beesint_threat_report import orchestrate
from beesint_threat_report.config import Settings

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/json_online/"
IPAPI_URL = "http://ip-api.com/batch"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
SHODAN_URL_REGEX = r"https://internetdb\.shodan\.io/.*"
SPAMHAUS_DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
SPAMHAUS_EDROP_URL = "https://www.spamhaus.org/drop/edrop.txt"

BUCKET = "test-threat-report-bucket"


@pytest.fixture
def moto_server():
    # ThreadedMotoServer expose un vrai serveur HTTP local — s3fs utilise aiobotocore
    # (async), que le mock_aws in-process de moto ne sait pas intercepter correctement
    # (bug connu moto/aiobotocore : réponses non-awaitable). Un vrai serveur HTTP contourne
    # le problème puisque aiohttp reçoit une vraie réponse HTTP.
    server = ThreadedMotoServer(port=0)
    server.start()
    port = server._server.socket.getsockname()[1]
    endpoint = f"http://127.0.0.1:{port}"
    boto3.client(
        "s3",
        region_name="us-east-1",
        endpoint_url=endpoint,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    ).create_bucket(Bucket=BUCKET)
    yield endpoint
    server.stop()


def _s3_client(endpoint):
    return boto3.client(
        "s3",
        region_name="us-east-1",
        endpoint_url=endpoint,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )


def _settings(tmp_path, endpoint: str, threatfox_auth_key: str | None = None) -> Settings:
    return Settings(
        storage_backend="s3",
        s3_bucket=BUCKET,
        s3_endpoint_url=endpoint,
        s3_access_key="test",
        s3_secret_key="test",
        cache_dir=tmp_path / ".cache",
        local_data_dir=tmp_path / ".data",
        threatfox_auth_key=threatfox_auth_key,
    )


def _kev_fixture_within_current_window() -> dict:
    # les dates de la fixture sont figées ; le run calcule sa fenêtre par rapport à "now"
    # réel — on recale les 2 entrées "récentes" pour qu'elles tombent dans [now-7j, now]
    # quel que soit le jour d'exécution du test, sans changer le fichier fixture statique.
    fixture = load_fixture("kev_feed.json")
    now = datetime.now(UTC)
    fixture["vulnerabilities"][0]["dateAdded"] = (now - timedelta(days=2)).strftime("%Y-%m-%d")
    fixture["vulnerabilities"][2]["dateAdded"] = (now - timedelta(days=1)).strftime("%Y-%m-%d")
    return fixture


def _stub_render_pdf(context, output_path):
    # évite de coupler ce test d'orchestration/S3 à la disponibilité de Pango/GTK sur la
    # machine (cf. CDC §24) — le rendu PDF réel est couvert par test_load_pdf_renderer.py.
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(b"%PDF-1.4 stub")
    return output_path


def _mock_all_sources(mock, feodo_up: bool = True):
    mock.get(NVD_URL).mock(return_value=httpx.Response(200, json=load_fixture("nvd_response.json")))
    mock.get(KEV_URL).mock(return_value=httpx.Response(200, json=_kev_fixture_within_current_window()))
    if feodo_up:
        mock.get(FEODO_URL).mock(return_value=httpx.Response(200, json=load_fixture("feodo_ipblocklist.json")))
    else:
        mock.get(FEODO_URL).mock(side_effect=httpx.ConnectError("network down"))
    mock.get(URLHAUS_URL).mock(return_value=httpx.Response(200, json=load_fixture("urlhaus_online.json")))
    mock.post(IPAPI_URL).mock(return_value=httpx.Response(200, json=load_fixture("ip_api_batch_response.json")))
    # Shodan InternetDB (1 requête par IP top-N) et Spamhaus DROP/EDROP (1 requête chacun) —
    # nouvelles sources d'enrichissement C2 toujours appelées sans clé dès que ip_list est non
    # vide. Mockées en "pas de données" : leur merge/format est déjà testé dans
    # test_pdf_context.py / test_orchestrate_new_sources.py, ce fichier ne teste que
    # l'orchestration S3/statuts qui ne doit pas changer de comportement à cause d'elles.
    mock.get(url__regex=SHODAN_URL_REGEX).mock(return_value=httpx.Response(404))
    mock.get(SPAMHAUS_DROP_URL).mock(return_value=httpx.Response(200, text="; empty\n"))
    mock.get(SPAMHAUS_EDROP_URL).mock(return_value=httpx.Response(200, text="; empty\n"))


@pytest.mark.asyncio
async def test_orchestrate_e2e_success_writes_all_artifacts_with_run_id(tmp_path, monkeypatch, moto_server):
    monkeypatch.setattr(orchestrate, "load_settings", lambda: _settings(tmp_path, moto_server))
    monkeypatch.setattr(orchestrate, "render_pdf", _stub_render_pdf)

    with respx.mock() as mock:
        _mock_all_sources(mock)
        payload = await orchestrate.run()

    assert payload["status"] == "success"
    run_id = payload["run_id"]

    keys = [obj["Key"] for obj in _s3_client(moto_server).list_objects_v2(Bucket=BUCKET).get("Contents", [])]

    assert "manifest.json" in keys
    assert "runs/index.json" in keys
    assert any(k.startswith("reports/report-") and run_id in k for k in keys)
    assert any(k.startswith("history/nvd/") and run_id in k for k in keys)
    assert any(k.startswith("history/kev/") and run_id in k for k in keys)
    assert any(k.startswith("history/feodo/") and run_id in k for k in keys)
    assert any(k.startswith("history/urlhaus/") and run_id in k for k in keys)


@pytest.mark.asyncio
async def test_orchestrate_e2e_degraded_source_still_produces_partial_report(tmp_path, monkeypatch, moto_server):
    monkeypatch.setattr(orchestrate, "load_settings", lambda: _settings(tmp_path, moto_server))

    # Feodo échoue entièrement -> aucune IP retenue -> geoloc/ip-api jamais appelé,
    # c'est le comportement attendu (pas tous les routes mockées ne sont donc sollicitées).
    with respx.mock(assert_all_called=False) as mock:
        _mock_all_sources(mock, feodo_up=False)
        payload = await orchestrate.run()

    assert payload["status"] == "partial"
    assert payload["sources_status"]["feodo"] == "failed"
    # les autres sources restent présentes dans le rapport
    assert payload["sources_status"]["nvd"] == "ok"
    assert payload["sources_status"]["kev"] == "ok"
    assert payload["sources_status"]["urlhaus"] == "ok"
    assert len(payload["cves"]) > 0


@pytest.mark.asyncio
async def test_orchestrate_e2e_threatfox_active_merges_iocs_and_stays_success(tmp_path, monkeypatch, moto_server):
    # équivalent local du "run manuel workflow_dispatch avec ThreatFox actif" (lot 7 DoD) —
    # le vrai run cloud avec Auth-Key réelle reste à exécuter manuellement par l'utilisateur
    # (aucun outillage cloud exécuté par l'assistant, cf. CDC §1).
    monkeypatch.setattr(orchestrate, "load_settings", lambda: _settings(tmp_path, moto_server, "secret-key"))
    monkeypatch.setattr(orchestrate, "render_pdf", _stub_render_pdf)

    with respx.mock() as mock:
        _mock_all_sources(mock)
        route = mock.post(THREATFOX_URL).mock(
            return_value=httpx.Response(200, json=load_fixture("threatfox_get_iocs.json"))
        )
        payload = await orchestrate.run()

    assert route.called
    assert payload["status"] == "success"
    assert payload["sources_status"]["threatfox"] == "ok"
    # 203.0.113.10 est aussi une IP feodo (fixture feodo_ipblocklist.json) -> fusion attendue
    merged = next((ip for ip in payload["malicious_ips"] if ip["ip"] == "203.0.113.10"), None)
    assert merged is not None
    assert merged["source"] == "feodo+threatfox"
    # TrickBot (domain) + Dridex (md5_hash) dans la fixture threatfox -> 2 familles
    assert payload["kpis"]["threatfox_malware_families_count"] == 2
