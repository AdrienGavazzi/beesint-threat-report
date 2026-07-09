from datetime import UTC

import httpx
import pytest
import respx
from conftest import load_fixture

from beesint_threat_report import backfill
from beesint_threat_report.config import Settings
from beesint_threat_report.extract import feodo, urlhaus

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _settings(tmp_path) -> Settings:
    return Settings(
        storage_backend="local",
        cache_dir=tmp_path / ".cache",
        local_data_dir=tmp_path / ".data",
    )


@pytest.mark.asyncio
async def test_backfill_never_calls_feodo_or_urlhaus(tmp_path, monkeypatch):
    monkeypatch.setattr(backfill, "load_settings", lambda: _settings(tmp_path))

    feodo_calls = []
    urlhaus_calls = []

    async def _fake_feodo(*args, **kwargs):
        feodo_calls.append(1)
        return []

    async def _fake_urlhaus(*args, **kwargs):
        urlhaus_calls.append(1)
        return []

    monkeypatch.setattr(feodo, "fetch_feodo_snapshot", _fake_feodo)
    monkeypatch.setattr(urlhaus, "fetch_urlhaus_online", _fake_urlhaus)

    with respx.mock() as mock:
        mock.get(NVD_URL).mock(return_value=httpx.Response(200, json=load_fixture("nvd_response.json")))
        kev_route = mock.get(KEV_URL).mock(return_value=httpx.Response(200, json=load_fixture("kev_feed.json")))
        await backfill.backfill(periods_back=3)

    assert feodo_calls == []
    assert urlhaus_calls == []
    # pull KEV complet fait une seule fois, pas une fois par fenêtre
    assert kev_route.call_count == 1


@pytest.mark.asyncio
async def test_backfill_writes_n_rolling_windows_no_manifest_no_index(tmp_path, monkeypatch):
    monkeypatch.setattr(backfill, "load_settings", lambda: _settings(tmp_path))

    with respx.mock() as mock:
        mock.get(NVD_URL).mock(return_value=httpx.Response(200, json=load_fixture("nvd_response.json")))
        mock.get(KEV_URL).mock(return_value=httpx.Response(200, json=load_fixture("kev_feed.json")))
        await backfill.backfill(periods_back=3)

    nvd_history = list((tmp_path / ".data" / "history" / "nvd").glob("period_end=*/run-*.parquet"))
    kev_history = list((tmp_path / ".data" / "history" / "kev").glob("period_end=*/run-*.parquet"))
    assert len(nvd_history) == 3
    assert len(kev_history) == 3

    assert not (tmp_path / ".data" / "manifest.json").exists()
    assert not (tmp_path / ".data" / "runs" / "index.json").exists()


def test_rolling_windows_most_recent_last():
    from datetime import datetime

    now = datetime(2026, 7, 9, tzinfo=UTC)
    windows = backfill._rolling_windows(3, now)
    assert len(windows) == 3
    assert windows[-1][1] == now
    assert windows[0][0] < windows[1][0] < windows[2][0]
