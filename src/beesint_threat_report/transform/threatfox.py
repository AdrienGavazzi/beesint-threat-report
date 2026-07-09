from __future__ import annotations

import polars as pl

from beesint_threat_report.validate.schemas import ThreatFoxIoc

_NEW_ROW_SCHEMA = {
    "ip_address": pl.Utf8,
    "status": pl.Utf8,
    "malware": pl.Utf8,
    "first_seen": pl.Datetime("us", "UTC"),
    "last_online": pl.Datetime("us", "UTC"),
    "country": pl.Utf8,
    "is_new": pl.Boolean,
    "source": pl.Utf8,
}


def merge_threatfox_ip_iocs(ip_frame: pl.DataFrame, threatfox_iocs: list[ThreatFoxIoc]) -> pl.DataFrame:
    """Fusionne les IOC ThreatFox de type ip:port dans ip_frame (colonne "source" étendue,
    dédup par IP — cf. lot 7). Domaine/hash ignorés ici (alimentent le KPI agrégé, kpis.py)."""
    if ip_frame.height and "source" not in ip_frame.columns:
        ip_frame = ip_frame.with_columns(pl.lit("feodo").alias("source"))

    ip_iocs = [ioc for ioc in threatfox_iocs if ioc.ioc_type == "ip:port"]
    if not ip_iocs:
        return ip_frame

    by_ip: dict[str, ThreatFoxIoc] = {}
    for ioc in ip_iocs:
        ip = ioc.ioc_value.split(":")[0]
        existing = by_ip.get(ip)
        if existing is None or ioc.first_seen > existing.first_seen:
            by_ip[ip] = ioc
    threatfox_ips = set(by_ip)

    matched_ips: set[str] = set()
    if ip_frame.height:
        ip_frame = ip_frame.with_columns(
            pl.when(pl.col("ip_address").is_in(threatfox_ips))
            .then(pl.col("source") + "+threatfox")
            .otherwise(pl.col("source"))
            .alias("source")
        )
        matched_ips = set(ip_frame["ip_address"].to_list()) & threatfox_ips

    new_ips = threatfox_ips - matched_ips
    if not new_ips:
        return ip_frame

    new_rows = [
        {
            "ip_address": ip,
            "status": "online",
            "malware": by_ip[ip].malware_printable,
            "first_seen": by_ip[ip].first_seen,
            "last_online": by_ip[ip].last_seen,
            "country": None,
            "is_new": None,
            "source": "threatfox",
        }
        for ip in new_ips
    ]
    new_df = pl.DataFrame(new_rows, schema=_NEW_ROW_SCHEMA)
    if ip_frame.height:
        # une colonne 100% null côté ip_frame (ex. last_online jamais renseigné) s'infère
        # en dtype Null, incompatible avec le dtype déclaré de new_df pour
        # pl.concat(how="vertical") — on recale ces colonnes sur le dtype de new_df.
        null_cols = [c for c in ip_frame.columns if c in new_df.schema and ip_frame.schema[c] == pl.Null]
        if null_cols:
            ip_frame = ip_frame.with_columns([pl.col(c).cast(new_df.schema[c]) for c in null_cols])
        return pl.concat([ip_frame, new_df.select(ip_frame.columns)], how="vertical")
    return new_df
