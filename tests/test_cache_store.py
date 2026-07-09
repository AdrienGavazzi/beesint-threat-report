import json

import pytest

from beesint_threat_report.cache.store import cache_key, get_or_fetch


def test_cache_key_deterministic():
    assert cache_key("nvd", {"a": 1, "b": 2}) == cache_key("nvd", {"b": 2, "a": 1})
    assert cache_key("nvd", {"a": 1}) != cache_key("kev", {"a": 1})


@pytest.mark.asyncio
async def test_get_or_fetch_miss_calls_fetch_once(tmp_path):
    calls = []

    async def fetch_fn():
        calls.append(1)
        return [{"x": 1}]

    result = await get_or_fetch("k", fetch_fn, tmp_path, force_refresh=False)
    assert result == [{"x": 1}]
    assert len(calls) == 1
    assert (tmp_path / "k.json").exists()


@pytest.mark.asyncio
async def test_get_or_fetch_hit_never_calls_fetch(tmp_path):
    (tmp_path / "k.json").write_text(json.dumps([{"x": 2}]), encoding="utf-8")

    async def fetch_fn():
        raise AssertionError("fetch_fn ne doit jamais être appelé sur un cache hit")

    result = await get_or_fetch("k", fetch_fn, tmp_path, force_refresh=False)
    assert result == [{"x": 2}]


@pytest.mark.asyncio
async def test_get_or_fetch_force_refresh_always_calls_fetch(tmp_path):
    (tmp_path / "k.json").write_text(json.dumps([{"x": 2}]), encoding="utf-8")
    calls = []

    async def fetch_fn():
        calls.append(1)
        return [{"x": 3}]

    result = await get_or_fetch("k", fetch_fn, tmp_path, force_refresh=True)
    assert result == [{"x": 3}]
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_get_or_fetch_ttl_expired_treated_as_miss(tmp_path, monkeypatch):
    cache_path = tmp_path / "k.json"
    cache_path.write_text(json.dumps([{"x": 2}]), encoding="utf-8")

    import beesint_threat_report.cache.store as store_module

    monkeypatch.setattr(store_module.time, "time", lambda: cache_path.stat().st_mtime + 1000)

    calls = []

    async def fetch_fn():
        calls.append(1)
        return [{"x": 4}]

    result = await get_or_fetch("k", fetch_fn, tmp_path, force_refresh=False, ttl_seconds=10)
    assert result == [{"x": 4}]
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_get_or_fetch_corrupted_cache_treated_as_miss_no_crash(tmp_path):
    cache_path = tmp_path / "k.json"
    cache_path.write_text("not valid json{{{", encoding="utf-8")

    async def fetch_fn():
        return [{"x": 5}]

    result = await get_or_fetch("k", fetch_fn, tmp_path, force_refresh=False)
    assert result == [{"x": 5}]
