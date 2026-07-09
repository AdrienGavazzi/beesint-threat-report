from datetime import UTC, datetime

import pandera.errors
import polars as pl
import pytest

from beesint_threat_report.validate.frames import (
    validate_cve_frame,
    validate_feodo_frame,
    validate_kev_frame,
    validate_urlhaus_frame,
)


def _utc(*args) -> datetime:
    return datetime(*args, tzinfo=UTC)


def test_validate_cve_frame_valid_passes():
    df = pl.DataFrame(
        {
            "cve_id": ["CVE-2026-10001", "CVE-2026-10002"],
            "published_date": [_utc(2026, 6, 1), _utc(2026, 6, 2)],
            "cvss_v3_score": [9.8, 8.6],
            "cvss_v3_severity": ["CRITICAL", "HIGH"],
            "vendor": ["acme", None],
        }
    )
    result = validate_cve_frame(df)
    assert result.height == 2


def test_validate_cve_frame_invalid_accumulates_multiple_errors():
    # colonne cvss_v3_score hors plage [0,10] ET doublon sur cve_id (unique=True) simultanément
    df = pl.DataFrame(
        {
            "cve_id": ["CVE-2026-10001", "CVE-2026-10001"],
            "published_date": [_utc(2026, 6, 1), _utc(2026, 6, 2)],
            "cvss_v3_score": [99.0, 8.6],
            "cvss_v3_severity": ["CRITICAL", "HIGH"],
            "vendor": ["acme", None],
        }
    )
    with pytest.raises(pandera.errors.SchemaErrors) as exc_info:
        validate_cve_frame(df)
    failure_cases = exc_info.value.failure_cases
    # au moins 2 échecs différents accumulés (score hors plage + doublon), pas juste le premier
    assert len(failure_cases) >= 2


def test_validate_kev_frame_missing_column_raises():
    df = pl.DataFrame(
        {
            "cve_id": ["CVE-2026-10001"],
            "date_added": [_utc(2026, 6, 5)],
            # "due_date" manquant
            "known_ransomware_campaign_use": ["Known"],
        }
    )
    with pytest.raises(pandera.errors.SchemaErrors):
        validate_kev_frame(df)


def test_validate_feodo_frame_valid_passes():
    df = pl.DataFrame(
        {
            "ip_address": ["203.0.113.10", "198.51.100.20"],
            "status": ["online", "offline"],
            "first_seen": [_utc(2026, 5, 1), _utc(2026, 4, 15)],
            "is_new": pl.Series([None, None], dtype=pl.Boolean),
        }
    )
    result = validate_feodo_frame(df)
    assert result.height == 2


def test_validate_urlhaus_frame_duplicate_url_raises():
    df = pl.DataFrame(
        {
            "url": ["http://evil.example/a", "http://evil.example/a"],
            "url_status": ["online", "online"],
            "date_added": [_utc(2026, 6, 1), _utc(2026, 6, 2)],
            "is_new": pl.Series([None, None], dtype=pl.Boolean),
        }
    )
    with pytest.raises(pandera.errors.SchemaErrors):
        validate_urlhaus_frame(df)
