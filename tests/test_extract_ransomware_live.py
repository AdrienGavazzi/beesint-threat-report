from datetime import UTC, datetime

import httpx
import pytest
import respx

from beesint_threat_report.extract.ransomware_live import (
    fetch_ransomware_groups,
    fetch_ransomware_posts,
    filter_posts_by_window,
    filter_posts_last_n_weeks,
    normalize_group_name,
)
from beesint_threat_report.validate.schemas import RansomwarePost, validate_batch

POSTS_URL = "https://data.ransomware.live/posts.json"
GROUPS_URL = "https://data.ransomware.live/groups.json"


# ---- garantie éthique : post_title/website/post_url ne survivent jamais, à aucune étape -------


@pytest.mark.asyncio
async def test_fetch_ransomware_posts_never_carries_victim_identifying_fields():
    raw_post = {
        "group_name": "lockbit3",
        "activity": "Healthcare",
        "country": "US",
        "discovered": "2026-07-18T11:59:18+00:00",
        "published": "2026-07-18T11:46:41+00:00",
        # Champs réels de la source — présents dans le dict brut, ne doivent JAMAIS ressortir.
        "post_title": "Some Victim Corp",
        "website": "victimcorp.example.com",
        "post_url": "http://leaksiteexample.onion/blog/victim",
    }
    with respx.mock() as mock:
        mock.get(POSTS_URL).mock(return_value=httpx.Response(200, json=[raw_post]))
        async with httpx.AsyncClient() as client:
            mapped = await fetch_ransomware_posts(client, POSTS_URL)

    assert len(mapped) == 1
    assert "post_title" not in mapped[0]
    assert "website" not in mapped[0]
    assert "post_url" not in mapped[0]


def test_ransomware_post_model_drops_victim_fields_even_if_present_in_raw_dict():
    """Deuxième filet de sécurité, indépendant du mapper : même un dict brut construit à la main
    avec les 3 champs interdits ne doit jamais les faire survivre à model_validate()."""
    raw = {
        "group_name": "lockbit3",
        "activity": "Healthcare",
        "country": "US",
        "discovered": "2026-07-18T11:59:18+00:00",
        "post_title": "Some Victim Corp",
        "website": "victimcorp.example.com",
        "post_url": "http://leaksiteexample.onion/blog/victim",
    }
    valid, rejected = validate_batch([raw], RansomwarePost, source="ransomware_live", run_id="run-1")
    assert rejected == []
    assert len(valid) == 1
    dumped = valid[0].model_dump()
    assert "post_title" not in dumped
    assert "website" not in dumped
    assert "post_url" not in dumped


# ---- normalisation nom de groupe (casse/espaces) ----------------------------------------------


def test_normalize_group_name_strips_case_and_whitespace():
    assert normalize_group_name("LockBit3") == "lockbit3"
    assert normalize_group_name("  Akira  ") == "akira"
    assert normalize_group_name("lockbit3") == normalize_group_name(" LockBit3 ")


# ---- filtrage par fenêtre (avant validation, sur les dicts bruts) -----------------------------


def test_filter_posts_by_window_keeps_only_posts_in_range():
    posts = [
        {"group_name": "a", "discovered": "2026-07-10T00:00:00+00:00"},
        {"group_name": "b", "discovered": "2026-07-15T00:00:00+00:00"},
        {"group_name": "c", "discovered": "2026-06-01T00:00:00+00:00"},
    ]
    period_start = datetime(2026, 7, 8, tzinfo=UTC)
    period_end = datetime(2026, 7, 18, tzinfo=UTC)
    result = filter_posts_by_window(posts, period_start, period_end)
    assert {p["group_name"] for p in result} == {"a", "b"}


def test_filter_posts_by_window_skips_posts_missing_or_unparseable_date():
    posts = [
        {"group_name": "a", "discovered": None},
        {"group_name": "b"},
        {"group_name": "c", "discovered": "not-a-date"},
    ]
    result = filter_posts_by_window(posts, datetime(2020, 1, 1, tzinfo=UTC), datetime(2030, 1, 1, tzinfo=UTC))
    assert result == []


def test_filter_posts_last_n_weeks_wider_than_single_run_window():
    period_end = datetime(2026, 7, 18, tzinfo=UTC)
    posts = [
        {"group_name": "recent", "discovered": "2026-07-15T00:00:00+00:00"},
        {"group_name": "five_weeks_ago", "discovered": "2026-06-15T00:00:00+00:00"},
        {"group_name": "too_old", "discovered": "2026-01-01T00:00:00+00:00"},
    ]
    result = filter_posts_last_n_weeks(posts, period_end, weeks=6)
    assert {p["group_name"] for p in result} == {"recent", "five_weeks_ago"}


# ---- fetch_ransomware_groups --------------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_ransomware_groups_maps_fields_and_drops_locations():
    raw_group = {
        "name": "LockBit3",
        "altname": None,
        "lineage": None,
        "description": "Double-extortion RaaS.",
        "type": {"raas": True},
        "_victim_count": 42,
        "locations": [{"fqdn": "example.onion", "http": {}}],
    }
    with respx.mock() as mock:
        mock.get(GROUPS_URL).mock(return_value=httpx.Response(200, json=[raw_group]))
        async with httpx.AsyncClient() as client:
            mapped = await fetch_ransomware_groups(client, GROUPS_URL)

    assert mapped == [
        {
            "name": "LockBit3",
            "altname": None,
            "lineage": None,
            "description": "Double-extortion RaaS.",
            "is_raas": True,
            "victim_count_lifetime": 42,
        }
    ]
    assert "locations" not in mapped[0]
