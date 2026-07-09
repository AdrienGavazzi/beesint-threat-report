from __future__ import annotations

import pandera.polars as pa
import polars as pl

# UTC unique point d'entrée (CDC §12) — tous les champs datetime sont tz-aware UTC dès
# validate/schemas.py (Pydantic), le schéma Pandera post-transform doit matcher ce dtype exact.
_UTC_DATETIME = pl.Datetime("us", "UTC")

CveFrameSchema = pa.DataFrameSchema(
    {
        "cve_id": pa.Column(pl.Utf8, pa.Check.str_matches(r"^CVE-\d{4}-\d{4,}$"), unique=True),
        "published_date": pa.Column(_UTC_DATETIME),
        "cvss_v3_score": pa.Column(pl.Float64, pa.Check.in_range(0.0, 10.0), nullable=True),
        "cvss_v3_severity": pa.Column(pl.Utf8, pa.Check.isin(["CRITICAL", "HIGH", "MEDIUM", "LOW"]), nullable=True),
        "vendor": pa.Column(pl.Utf8, nullable=True),
    },
    strict=False,
)

KevFrameSchema = pa.DataFrameSchema(
    {
        "cve_id": pa.Column(pl.Utf8, pa.Check.str_matches(r"^CVE-\d{4}-\d{4,}$"), unique=True),
        "date_added": pa.Column(_UTC_DATETIME),
        "due_date": pa.Column(_UTC_DATETIME),
        "known_ransomware_campaign_use": pa.Column(pl.Utf8, pa.Check.isin(["Known", "Unknown"])),
    },
    strict=False,
)

FeodoFrameSchema = pa.DataFrameSchema(
    {
        "ip_address": pa.Column(pl.Utf8, unique=True),
        "status": pa.Column(pl.Utf8, pa.Check.isin(["online", "offline"])),
        "first_seen": pa.Column(_UTC_DATETIME),
        "is_new": pa.Column(pl.Boolean, nullable=True),
    },
    strict=False,
)

UrlhausFrameSchema = pa.DataFrameSchema(
    {
        "url": pa.Column(pl.Utf8, unique=True),
        "url_status": pa.Column(pl.Utf8, pa.Check.isin(["online", "offline"])),
        "date_added": pa.Column(_UTC_DATETIME),
        "is_new": pa.Column(pl.Boolean, nullable=True),
    },
    strict=False,
)


def validate_cve_frame(df: pl.DataFrame) -> pl.DataFrame:
    return CveFrameSchema.validate(df, lazy=True)


def validate_kev_frame(df: pl.DataFrame) -> pl.DataFrame:
    return KevFrameSchema.validate(df, lazy=True)


def validate_feodo_frame(df: pl.DataFrame) -> pl.DataFrame:
    return FeodoFrameSchema.validate(df, lazy=True)


def validate_urlhaus_frame(df: pl.DataFrame) -> pl.DataFrame:
    return UrlhausFrameSchema.validate(df, lazy=True)
