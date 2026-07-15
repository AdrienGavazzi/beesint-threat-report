from datetime import UTC, datetime

import polars as pl

from beesint_threat_report.transform.openphish_merge import _normalize_url, merge_openphish_urls
from beesint_threat_report.transform.ranking import rank_top_n_urls
from beesint_threat_report.validate.schemas import OpenPhishEntry


def _utc(*args) -> datetime:
    return datetime(*args, tzinfo=UTC)


def _entry(url="http://evil.example/login") -> OpenPhishEntry:
    return OpenPhishEntry(url=url)


def _base_urlhaus_df() -> pl.DataFrame:
    return pl.DataFrame(
        {
            "url": ["http://evil.example/login", "http://other.example/malware.exe"],
            "url_status": ["online", "online"],
            "date_added": [_utc(2026, 7, 1), _utc(2026, 7, 2)],
            "threat": ["phishing", "malware_download"],
            "tags": [["phish"], ["exe"]],
            "is_new": pl.Series([False, True], dtype=pl.Boolean),
        }
    )


# ---- _normalize_url ---------------------------------------------------------------------


def test_normalize_url_lowercases_scheme_and_host_strips_trailing_slash():
    assert _normalize_url("HTTP://Evil.Example/Path/") == _normalize_url("http://evil.example/Path")


def test_normalize_url_keeps_path_case_sensitive():
    assert _normalize_url("http://evil.example/Path") != _normalize_url("http://evil.example/path")


# ---- merge_openphish_urls: no openphish data -----------------------------------------------


def test_merge_no_openphish_entries_adds_default_sources_column():
    result = merge_openphish_urls(_base_urlhaus_df(), [], observed_at=_utc(2026, 7, 10))
    assert result["sources"].to_list() == [["urlhaus"], ["urlhaus"]]
    assert result.height == 2


def test_merge_empty_urlhaus_and_no_openphish_returns_empty():
    empty = pl.DataFrame(
        schema={
            "url": pl.Utf8,
            "url_status": pl.Utf8,
            "date_added": pl.Datetime,
            "threat": pl.Utf8,
            "tags": pl.List(pl.Utf8),
            "is_new": pl.Boolean,
        }
    )
    result = merge_openphish_urls(empty, [], observed_at=_utc(2026, 7, 10))
    assert result.height == 0


# ---- merge_openphish_urls: URL confirmed by both feeds -------------------------------------


def test_merge_url_in_both_feeds_becomes_one_row_with_both_sources():
    result = merge_openphish_urls(
        _base_urlhaus_df(), [_entry(url="http://evil.example/login")], observed_at=_utc(2026, 7, 10)
    )
    assert result.height == 2  # pas de doublon
    by_url = {row["url"]: row["sources"] for row in result.to_dicts()}
    assert sorted(by_url["http://evil.example/login"]) == ["openphish", "urlhaus"]
    assert by_url["http://other.example/malware.exe"] == ["urlhaus"]


def test_merge_matches_via_normalization_trailing_slash_and_case():
    result = merge_openphish_urls(
        _base_urlhaus_df(), [_entry(url="HTTP://Evil.Example/login/")], observed_at=_utc(2026, 7, 10)
    )
    assert result.height == 2
    row = next(r for r in result.to_dicts() if r["url"] == "http://evil.example/login")
    assert sorted(row["sources"]) == ["openphish", "urlhaus"]


# ---- merge_openphish_urls: openphish-only URL is a genuinely new row -----------------------


def test_merge_openphish_only_url_appends_new_row():
    observed = _utc(2026, 7, 10)
    result = merge_openphish_urls(_base_urlhaus_df(), [_entry(url="http://newphish.example/x")], observed_at=observed)
    assert result.height == 3
    row = next(r for r in result.to_dicts() if r["url"] == "http://newphish.example/x")
    assert row["sources"] == ["openphish"]
    assert row["threat"] == "phishing"
    assert row["is_new"] is True
    assert row["date_added"] == observed  # pas d'horodatage par URL côté OpenPhish, fallback = period_end du run


def test_merge_dedups_repeated_url_within_openphish_feed_itself():
    entries = [_entry(url="http://dup.example/a"), _entry(url="http://dup.example/a")]
    result = merge_openphish_urls(_base_urlhaus_df(), entries, observed_at=_utc(2026, 7, 10))
    assert result.height == 3  # 2 urlhaus + 1 seule ligne dup.example (pas 2)


def test_merge_empty_urlhaus_df_all_openphish_rows_are_new():
    empty = pl.DataFrame(
        schema={
            "url": pl.Utf8,
            "url_status": pl.Utf8,
            "date_added": pl.Datetime,
            "threat": pl.Utf8,
            "tags": pl.List(pl.Utf8),
            "is_new": pl.Boolean,
        }
    )
    result = merge_openphish_urls(empty, [_entry(url="http://onlyphish.example/a")], observed_at=_utc(2026, 7, 10))
    assert result.height == 1
    assert result["sources"].to_list() == [["openphish"]]


# ---- rank_top_n_urls: cross-confirmed entries sort ahead of single-source ------------------


def test_rank_top_n_urls_prioritizes_more_sources_over_is_new():
    df = pl.DataFrame(
        {
            "url": ["single-new.example", "confirmed-old.example"],
            "is_new": [True, False],
            "date_added": [_utc(2026, 7, 5), _utc(2026, 7, 1)],
            "sources": [["urlhaus"], ["urlhaus", "openphish"]],
        }
    )
    result = rank_top_n_urls(df, n=10)
    assert result["url"].to_list() == ["confirmed-old.example", "single-new.example"]


def test_rank_top_n_urls_without_sources_column_unchanged_behavior():
    df = pl.DataFrame(
        {
            "url": ["b.example", "a.example"],
            "is_new": [True, True],
            "date_added": [_utc(2026, 7, 1), _utc(2026, 7, 1)],
        }
    )
    result = rank_top_n_urls(df, n=10)
    assert result["url"].to_list() == ["a.example", "b.example"]
    assert "sources" not in result.columns
