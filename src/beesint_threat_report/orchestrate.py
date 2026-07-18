from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import httpx
import polars as pl

from beesint_threat_report.cache.store import cache_key, get_or_fetch
from beesint_threat_report.config import Settings, load_settings, resolve_base_path, resolve_storage_options
from beesint_threat_report.extract import (
    breachdirectory,
    feodo,
    greynoise,
    hibp,
    kev,
    nvd,
    openphish,
    shodan_internetdb,
    spamhaus_drop,
    threatfox,
    urlhaus,
)
from beesint_threat_report.load.json_writer import build_report_payload, write_report_json
from beesint_threat_report.load.parquet_writer import write_historical_parquet
from beesint_threat_report.load.pdf_context import (
    build_breach_items,
    build_c2_items,
    build_malicious_url_items,
    build_pdf_context,
)
from beesint_threat_report.load.pdf_renderer import render_pdf
from beesint_threat_report.publish.telemetry import log_run_summary, sentry_breadcrumb_run_step
from beesint_threat_report.publish.webhook import publish_status
from beesint_threat_report.transform import dedup, diffing, geoloc, mttk, ranking
from beesint_threat_report.transform import kpis as kpis_module
from beesint_threat_report.transform.openphish_merge import merge_openphish_urls
from beesint_threat_report.transform.threatfox import merge_threatfox_ip_iocs
from beesint_threat_report.validate.frames import (
    validate_cve_frame,
    validate_feodo_frame,
    validate_ip_threat_frame,
    validate_kev_frame,
    validate_urlhaus_frame,
)
from beesint_threat_report.validate.schemas import (
    BreachEntry,
    FeodoIpRecord,
    GreyNoiseClassification,
    KevEntry,
    NvdCveRecord,
    OpenPhishEntry,
    ShodanInternetDbRecord,
    SpamhausRange,
    ThreatFoxIoc,
    UrlhausEntry,
    validate_batch,
)

logger = logging.getLogger(__name__)

_CVE_EMPTY_SCHEMA = {
    "cve_id": pl.Utf8,
    "published_date": pl.Datetime,
    "cvss_v3_score": pl.Float64,
    "cvss_v3_severity": pl.Utf8,
    "vendor": pl.Utf8,
    "cwe_ids": pl.List(pl.Utf8),
    "description": pl.Utf8,
}
_KEV_EMPTY_SCHEMA = {
    "cve_id": pl.Utf8,
    "date_added": pl.Datetime,
    "due_date": pl.Datetime,
    "known_ransomware_campaign_use": pl.Utf8,
    "vendor_project": pl.Utf8,
    "product": pl.Utf8,
}
_FEODO_EMPTY_SCHEMA = {
    "ip_address": pl.Utf8,
    "status": pl.Utf8,
    "malware": pl.Utf8,
    "first_seen": pl.Datetime,
    "last_online": pl.Datetime,
    "country": pl.Utf8,
}
_URLHAUS_EMPTY_SCHEMA = {
    "url": pl.Utf8,
    "url_status": pl.Utf8,
    "date_added": pl.Datetime,
    "threat": pl.Utf8,
    "tags": pl.List(pl.Utf8),
}


def _records_to_frame(records: list, schema: dict) -> pl.DataFrame:
    if not records:
        return pl.DataFrame(schema=schema)
    rows = [r.model_dump() for r in records]
    return pl.DataFrame(rows).select(list(schema.keys()))


async def _fetch_geo_wrapped(client: httpx.AsyncClient, ip_records: list[FeodoIpRecord], batch_url: str) -> list[dict]:
    # cache.get_or_fetch attend list[dict] — le dict {ip: {...}} de geoloc est enveloppé
    # dans une liste à un élément pour respecter ce contrat générique.
    geo = await geoloc.enrich_ips_geoloc(client, ip_records, batch_url)
    return [geo]


def _read_json(base_path: str, storage_options: dict | None, relative_path: str):
    path = f"{base_path}/{relative_path}"
    if storage_options is None:
        p = Path(path)
        if not p.exists():
            return None
        return json.loads(p.read_text(encoding="utf-8"))
    import fsspec

    fs = fsspec.filesystem("s3", **storage_options)
    try:
        with fs.open(path, "r") as fh:
            return json.load(fh)
    except Exception:
        # objet absent (cold start) — toute erreur S3 ici est traitée comme "absent",
        # cohérent avec load_previous_snapshot (dégradation, jamais de crash sur lecture manquante)
        return None


def _write_json(base_path: str, storage_options: dict | None, relative_path: str, payload) -> None:
    path = f"{base_path}/{relative_path}"
    body = json.dumps(payload)
    if storage_options is None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(body, encoding="utf-8")
        return
    import fsspec

    fs = fsspec.filesystem("s3", **storage_options)
    with fs.open(path, "w") as fh:
        fh.write(body)


def _write_quarantine(
    base_path: str, storage_options: dict | None, source: str, run_id: str, rejected: list[dict]
) -> None:
    for index, item in enumerate(rejected):
        _write_json(base_path, storage_options, f"quarantine/{source}/{run_id}/{index}.json", item)
        try:
            import sentry_sdk

            sentry_sdk.capture_message(f"quarantine: {source} item {index} invalide")
        except Exception:
            pass


async def _run_nvd_source(
    client: httpx.AsyncClient,
    settings: Settings,
    run_id: str,
    period_start,
    period_end,
    base_path: str,
    storage_options: dict | None,
) -> tuple[pl.DataFrame, str, int]:
    try:
        # granularité jour (pas microseconde) — period_end dérive de datetime.now() à
        # chaque run, une clé au timestamp exact ne matcherait jamais deux runs successifs
        # et rendrait le cache inopérant (cf. test d'acceptation 2 "cache chaud").
        key = cache_key(
            "nvd",
            {
                "period_end_date": period_end.date().isoformat(),
                "window_days": settings.report_window_days,
                "max_results": settings.max_results_nvd,
            },
        )
        raw = await get_or_fetch(
            key,
            lambda: nvd.fetch_critical_cves(
                client,
                period_start,
                period_end,
                settings.nvd_api_key,
                settings.max_results_nvd,
                settings.nvd_base_url,
            ),
            settings.cache_dir,
            settings.force_refresh,
        )
        valid, rejected = validate_batch(raw, NvdCveRecord, source="nvd", run_id=run_id)
        _write_quarantine(base_path, storage_options, "nvd", run_id, rejected)
        deduped = dedup.dedup_cves(valid)
        df = _records_to_frame(deduped, _CVE_EMPTY_SCHEMA)
        if df.height:
            df = validate_cve_frame(df)

        high_key = cache_key(
            "nvd_high_count",
            {"period_end_date": period_end.date().isoformat(), "window_days": settings.report_window_days},
        )

        async def _fetch_high_count():
            count = await nvd.count_high_severity_cves(
                client, period_start, period_end, settings.nvd_api_key, settings.nvd_base_url
            )
            return [{"total": count}]

        high_raw = await get_or_fetch(high_key, _fetch_high_count, settings.cache_dir, settings.force_refresh)
        cve_high_count = high_raw[0]["total"] if high_raw else 0

        return df, "ok", cve_high_count
    except Exception:
        logger.exception("nvd: échec de la source, run continue en dégradé")
        return pl.DataFrame(schema=_CVE_EMPTY_SCHEMA), "failed", 0


async def _run_kev_source(
    client: httpx.AsyncClient,
    settings: Settings,
    run_id: str,
    period_start,
    period_end,
    base_path: str,
    storage_options: dict | None,
) -> tuple[pl.DataFrame, str]:
    try:
        key = cache_key("kev", {"feed_url": settings.kev_feed_url})
        raw = await get_or_fetch(
            key,
            lambda: kev.fetch_kev_feed(client, settings.kev_feed_url),
            settings.cache_dir,
            settings.force_refresh,
        )
        valid, rejected = validate_batch(raw, KevEntry, source="kev", run_id=run_id)
        _write_quarantine(base_path, storage_options, "kev", run_id, rejected)
        deduped = dedup.dedup_kev(valid)
        new_entries = kev.filter_new_entries(deduped, period_start, period_end)
        if len(new_entries) > settings.max_results_kev:
            logger.warning("kev: cap MAX_RESULTS_KEV=%s atteint, résultats tronqués", settings.max_results_kev)
            new_entries = new_entries[: settings.max_results_kev]
        df = _records_to_frame(new_entries, _KEV_EMPTY_SCHEMA)
        if df.height:
            df = validate_kev_frame(df)
        return df, "ok"
    except Exception:
        logger.exception("kev: échec de la source, run continue en dégradé")
        return pl.DataFrame(schema=_KEV_EMPTY_SCHEMA), "failed"


async def _run_feodo_source(
    client: httpx.AsyncClient,
    settings: Settings,
    run_id: str,
    manifest: dict | None,
    base_path: str,
    storage_options: dict | None,
) -> tuple[pl.DataFrame, str]:
    try:
        key = cache_key("feodo", {"feed_url": settings.feodo_feed_url})
        raw = await get_or_fetch(
            key,
            lambda: feodo.fetch_feodo_snapshot(client, settings.feodo_feed_url),
            settings.cache_dir,
            settings.force_refresh,
        )
        valid, rejected = validate_batch(raw, FeodoIpRecord, source="feodo", run_id=run_id)
        _write_quarantine(base_path, storage_options, "feodo", run_id, rejected)
        deduped = dedup.dedup_feodo(valid)
        df = _records_to_frame(deduped, _FEODO_EMPTY_SCHEMA)
        if df.height:
            df = validate_feodo_frame(df.with_columns(pl.lit(None, dtype=pl.Boolean).alias("is_new")))
            previous = diffing.load_previous_snapshot(manifest, "feodo", settings)
            df = diffing.diff_snapshots(df, previous, "ip_address")
        return df, "ok"
    except Exception:
        logger.exception("feodo: échec de la source, run continue en dégradé")
        return pl.DataFrame(schema=_FEODO_EMPTY_SCHEMA), "failed"


async def _run_urlhaus_source(
    client: httpx.AsyncClient,
    settings: Settings,
    run_id: str,
    manifest: dict | None,
    base_path: str,
    storage_options: dict | None,
) -> tuple[pl.DataFrame, str]:
    try:
        key = cache_key("urlhaus", {"feed_url": settings.urlhaus_feed_url})
        raw = await get_or_fetch(
            key,
            lambda: urlhaus.fetch_urlhaus_online(client, settings.urlhaus_feed_url),
            settings.cache_dir,
            settings.force_refresh,
        )
        valid, rejected = validate_batch(raw, UrlhausEntry, source="urlhaus", run_id=run_id)
        _write_quarantine(base_path, storage_options, "urlhaus", run_id, rejected)
        deduped = dedup.dedup_urlhaus(valid)
        df = _records_to_frame(deduped, _URLHAUS_EMPTY_SCHEMA)
        if df.height:
            df = validate_urlhaus_frame(df.with_columns(pl.lit(None, dtype=pl.Boolean).alias("is_new")))
            previous = diffing.load_previous_snapshot(manifest, "urlhaus", settings)
            df = diffing.diff_snapshots(df, previous, "url")
        return df, "ok"
    except Exception:
        logger.exception("urlhaus: échec de la source, run continue en dégradé")
        return pl.DataFrame(schema=_URLHAUS_EMPTY_SCHEMA), "failed"


async def _run_threatfox_source(
    client: httpx.AsyncClient,
    settings: Settings,
    run_id: str,
    period_end,
    base_path: str,
    storage_options: dict | None,
) -> tuple[list[ThreatFoxIoc], str]:
    if not settings.threatfox_auth_key:
        return [], "skipped:no_auth_key"
    try:
        key = cache_key(
            "threatfox",
            {"period_end_date": period_end.date().isoformat(), "days": settings.report_window_days},
        )
        raw = await get_or_fetch(
            key,
            lambda: threatfox.fetch_threatfox(
                client, settings.threatfox_auth_key, settings.report_window_days, settings.threatfox_base_url
            ),
            settings.cache_dir,
            settings.force_refresh,
        )
        valid, rejected = validate_batch(raw, ThreatFoxIoc, source="threatfox", run_id=run_id)
        _write_quarantine(base_path, storage_options, "threatfox", run_id, rejected)
        return valid, "ok"
    except threatfox.ThreatFoxAuthError:
        logger.warning("threatfox: Auth-Key invalide, étape ignorée")
        return [], "skipped:invalid_auth_key"
    except Exception:
        logger.exception("threatfox: échec de la source, run continue en dégradé")
        return [], "failed"


async def _run_shodan_source(
    client: httpx.AsyncClient,
    settings: Settings,
    run_id: str,
    ips: list[str],
    base_path: str,
    storage_options: dict | None,
) -> tuple[dict[str, dict], str]:
    """N'appelle Shodan InternetDB QUE sur `ips` — déjà réduit au top-N post rank_top_n_ips par
    l'appelant (run()), jamais sur le feed FeodoTracker complet non trié (CDC §"Data source
    integration rule")."""
    if not ips:
        return {}, "skipped:no_c2_ips"
    try:
        key = cache_key("shodan_internetdb", {"ips": sorted(ips)})
        raw = await get_or_fetch(
            key,
            lambda: shodan_internetdb.fetch_internetdb_for_ips(client, ips, settings.shodan_internetdb_base_url),
            settings.cache_dir,
            settings.force_refresh,
        )
        valid, rejected = validate_batch(raw, ShodanInternetDbRecord, source="shodan_internetdb", run_id=run_id)
        _write_quarantine(base_path, storage_options, "shodan_internetdb", run_id, rejected)
        return {r.ip: {"ports": r.ports, "vulns": r.vulns} for r in valid}, "ok"
    except Exception:
        logger.exception("shodan_internetdb: échec de la source, run continue en dégradé")
        return {}, "failed"


async def _run_spamhaus_source(
    client: httpx.AsyncClient,
    settings: Settings,
    run_id: str,
    ips: list[str],
    base_path: str,
    storage_options: dict | None,
) -> tuple[set[str], str]:
    if not ips:
        return set(), "skipped:no_c2_ips"
    try:
        # clé stable (pas par IP) : DROP+EDROP se téléchargent une seule fois par run, pas une
        # fois par IP contrairement à Shodan/GreyNoise (cf. extract/spamhaus_drop.py).
        key = cache_key(
            "spamhaus_drop", {"drop_url": settings.spamhaus_drop_url, "edrop_url": settings.spamhaus_edrop_url}
        )
        raw = await get_or_fetch(
            key,
            lambda: spamhaus_drop.fetch_spamhaus_ranges(
                client, settings.spamhaus_drop_url, settings.spamhaus_edrop_url
            ),
            settings.cache_dir,
            settings.force_refresh,
        )
        valid, rejected = validate_batch(raw, SpamhausRange, source="spamhaus_drop", run_id=run_id)
        _write_quarantine(base_path, storage_options, "spamhaus_drop", run_id, rejected)
        confirmed = spamhaus_drop.match_ips_against_ranges(ips, [r.cidr for r in valid])
        return confirmed, "ok"
    except Exception:
        logger.exception("spamhaus_drop: échec de la source, run continue en dégradé")
        return set(), "failed"


async def _run_greynoise_source(
    client: httpx.AsyncClient,
    settings: Settings,
    run_id: str,
    ips: list[str],
    base_path: str,
    storage_options: dict | None,
) -> tuple[dict[str, str], str]:
    if not settings.greynoise_api_key:
        return {}, "skipped:no_api_key"
    if not ips:
        return {}, "skipped:no_c2_ips"
    try:
        key = cache_key("greynoise", {"ips": sorted(ips)})
        raw = await get_or_fetch(
            key,
            lambda: greynoise.fetch_greynoise_classifications(
                client, ips, settings.greynoise_api_key, settings.greynoise_base_url
            ),
            settings.cache_dir,
            settings.force_refresh,
        )
        valid, rejected = validate_batch(raw, GreyNoiseClassification, source="greynoise", run_id=run_id)
        _write_quarantine(base_path, storage_options, "greynoise", run_id, rejected)
        return {r.ip: r.classification for r in valid}, "ok"
    except Exception:
        logger.exception("greynoise: échec de la source, run continue en dégradé")
        return {}, "failed"


async def _run_openphish_source(
    client: httpx.AsyncClient,
    settings: Settings,
    run_id: str,
    period_end,
    base_path: str,
    storage_options: dict | None,
) -> tuple[list[OpenPhishEntry], str]:
    """Remplace _run_phishtank_source (PhishTank : inscriptions fermées, plus de clé obtenable).
    OpenPhish est un flux public gratuit, aucune clé requise — jamais "skipped:no_api_key"."""
    try:
        key = cache_key("openphish", {"period_end_date": period_end.date().isoformat()})
        raw = await get_or_fetch(
            key,
            lambda: openphish.fetch_openphish_feed(client, settings.openphish_feed_url),
            settings.cache_dir,
            settings.force_refresh,
        )
        valid, rejected = validate_batch(raw, OpenPhishEntry, source="openphish", run_id=run_id)
        _write_quarantine(base_path, storage_options, "openphish", run_id, rejected)
        return valid, "ok"
    except Exception:
        logger.exception("openphish: échec de la source, run continue en dégradé")
        return [], "failed"


async def _run_hibp_source(
    client: httpx.AsyncClient,
    settings: Settings,
    run_id: str,
    period_start,
    period_end,
    base_path: str,
    storage_options: dict | None,
) -> tuple[list[BreachEntry], str]:
    """Breaches This Week (CDC Phase P5) — HaveIBeenPwned, gratuit sans clé. Même style
    list-based que ThreatFox/OpenPhish (pas de DataFrame, pas de dedup — HIBP "Name" est déjà
    unique par construction sur un même pull)."""
    try:
        key = cache_key("hibp", {"breaches_url": settings.hibp_breaches_url})
        raw = await get_or_fetch(
            key,
            lambda: hibp.fetch_hibp_breaches(client, settings.hibp_breaches_url),
            settings.cache_dir,
            settings.force_refresh,
        )
        valid, rejected = validate_batch(raw, BreachEntry, source="hibp", run_id=run_id)
        _write_quarantine(base_path, storage_options, "hibp", run_id, rejected)
        new_entries = hibp.filter_new_breaches(valid, period_start, period_end)
        return new_entries, "ok"
    except Exception:
        logger.exception("hibp: échec de la source, run continue en dégradé")
        return [], "failed"


async def _run_breachdirectory_source(
    client: httpx.AsyncClient,
    settings: Settings,
    domain: str | None,
) -> tuple[int, str]:
    """Cross-check secondaire (CDC Phase P5) — appelé une seule fois sur le domaine de la breach
    la plus impactante du run ("spotlight"), jamais bloquant : pas de clé -> skip avant tout appel
    réseau (même convention que _run_greynoise_source/_run_shodan_source sans IP)."""
    if not settings.rapidapi_key:
        return 0, "skipped:no_api_key"
    if not domain:
        return 0, "skipped:no_breach_this_run"
    try:
        found = await breachdirectory.check_breachdirectory(client, domain, settings.rapidapi_key)
        return found, "ok"
    except Exception:
        logger.exception("breachdirectory: échec de la source, run continue en dégradé")
        return 0, "failed"


def _build_top_cves(ranked_cve_df: pl.DataFrame, kev_df: pl.DataFrame) -> list[dict]:
    if ranked_cve_df.height == 0:
        return []
    kev_by_id = {row["cve_id"]: row for row in kev_df.to_dicts()} if kev_df.height else {}
    result = []
    for row in ranked_cve_df.to_dicts():
        kev_row = kev_by_id.get(row["cve_id"])
        cwe_ids = row.get("cwe_ids") or []
        result.append(
            {
                "cve_id": row["cve_id"],
                "description": row.get("description"),
                # round() : évite un artefact d'affichage type "9.700000000000001" si une valeur a
                # transité par une opération flottante en amont (tri/agrégation Polars) plutôt que
                # d'arriver telle quelle depuis le JSON NVD.
                "cvss_score": round(v, 1) if (v := row.get("cvss_v3_score")) is not None else None,
                "severity": row.get("cvss_v3_severity"),
                "vendor": row.get("vendor"),
                "product": None,
                "cwe": cwe_ids[0] if cwe_ids else None,
                "is_kev": kev_row is not None,
                "is_ransomware": bool(kev_row and kev_row.get("known_ransomware_campaign_use") == "Known"),
                "published_date": row["published_date"].isoformat()
                if hasattr(row["published_date"], "isoformat")
                else row["published_date"],
                "kev_added_date": kev_row["date_added"].isoformat()
                if kev_row and hasattr(kev_row["date_added"], "isoformat")
                else None,
            }
        )
    return result


def _build_top_ips(
    ranked_feodo_df: pl.DataFrame,
    geo: dict[str, dict],
    shodan: dict[str, dict] | None = None,
    spamhaus_confirmed: set[str] | None = None,
    greynoise_classifications: dict[str, str] | None = None,
) -> list[dict]:
    if ranked_feodo_df.height == 0:
        return []
    shodan = shodan or {}
    spamhaus_confirmed = spamhaus_confirmed or set()
    greynoise_classifications = greynoise_classifications or {}
    result = []
    for row in ranked_feodo_df.to_dicts():
        ip = row["ip_address"]
        g = geo.get(ip, {})
        s = shodan.get(ip)
        result.append(
            {
                "ip": ip,
                "lat": g.get("lat"),
                "lon": g.get("lon"),
                "country": g.get("country") or row.get("country"),
                "city": g.get("city"),
                "asn": g.get("asn"),
                "malware": row.get("malware"),
                "source": row.get("source", "feodo"),
                "first_seen": row["first_seen"].isoformat()
                if hasattr(row["first_seen"], "isoformat")
                else row["first_seen"],
                "last_seen": row["last_online"].isoformat()
                if row.get("last_online") is not None and hasattr(row["last_online"], "isoformat")
                else None,
                # Enrichissement post rank_top_n_ips (Shodan InternetDB, Spamhaus DROP/EDROP,
                # GreyNoise) — jamais calculé sur le feed FeodoTracker complet, seulement sur ce
                # top-N déjà réduit (cf. CDC "Data source integration rule").
                "open_ports": s.get("ports", []) if s else [],
                "known_cves": s.get("vulns", []) if s else [],
                "shodan_has_data": s is not None,
                "confirmed_by_spamhaus": ip in spamhaus_confirmed,
                "greynoise_classification": greynoise_classifications.get(ip),
            }
        )
    return result


async def run(force_refresh: bool = False, skip_email: bool = False) -> dict:
    started_at = time.monotonic()
    settings = load_settings()
    settings = _override_force_refresh(settings, force_refresh)

    if settings.sentry_dsn:
        import sentry_sdk

        sentry_sdk.init(dsn=settings.sentry_dsn, environment=settings.environment)

    run_id = str(uuid4())
    period_end = datetime.now(UTC)
    period_start = period_end - timedelta(days=settings.report_window_days)

    # GITHUB_RUN_ID est fourni automatiquement par tout job GitHub Actions (pas besoin de le
    # déclarer dans le workflow) — remonté jusqu'au backend pour corréler un run interne à son
    # run GitHub Actions par ID exact plutôt que par une heuristique de proximité de timestamp
    # (tolérance 10 min côté backend, pouvait mal associer 2 runs proches).
    github_run_id = os.environ.get("GITHUB_RUN_ID") or None

    base_path = resolve_base_path(settings)
    storage_options = resolve_storage_options(settings)

    manifest = _read_json(base_path, storage_options, "manifest.json")
    is_cold_start = manifest is None

    sources_status: dict[str, str] = {}

    # follow_redirects=True : openphish.com/feed.txt répond en 302 vers GitHub — non suivi par
    # défaut par httpx, ce qui faisait ingérer la page HTML de redirection comme si c'était le
    # flux texte lui-même (root cause du parsing OpenPhish cassé, cf. CLAUDE.md racine).
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        cve_df, nvd_status, cve_high_count = await _run_nvd_source(
            client, settings, run_id, period_start, period_end, base_path, storage_options
        )
        sources_status["nvd"] = nvd_status
        sentry_breadcrumb_run_step("extract_nvd", nvd_status)

        kev_df, kev_status = await _run_kev_source(
            client, settings, run_id, period_start, period_end, base_path, storage_options
        )
        sources_status["kev"] = kev_status
        sentry_breadcrumb_run_step("extract_kev", kev_status)

        feodo_df, feodo_status = await _run_feodo_source(client, settings, run_id, manifest, base_path, storage_options)
        sources_status["feodo"] = feodo_status
        sentry_breadcrumb_run_step("extract_feodo", feodo_status)

        urlhaus_df, urlhaus_status = await _run_urlhaus_source(
            client, settings, run_id, manifest, base_path, storage_options
        )
        sources_status["urlhaus"] = urlhaus_status
        sentry_breadcrumb_run_step("extract_urlhaus", urlhaus_status)

        threatfox_iocs, threatfox_status = await _run_threatfox_source(
            client, settings, run_id, period_end, base_path, storage_options
        )
        sources_status["threatfox"] = threatfox_status
        sentry_breadcrumb_run_step("extract_threatfox", threatfox_status)

        openphish_entries, openphish_status = await _run_openphish_source(
            client, settings, run_id, period_end, base_path, storage_options
        )
        sources_status["openphish"] = openphish_status
        sentry_breadcrumb_run_step("extract_openphish", openphish_status)

        hibp_entries, hibp_status = await _run_hibp_source(
            client, settings, run_id, period_start, period_end, base_path, storage_options
        )
        sources_status["hibp"] = hibp_status
        sentry_breadcrumb_run_step("extract_hibp", hibp_status)

        ip_frame = merge_threatfox_ip_iocs(feodo_df, threatfox_iocs)
        if ip_frame.height:
            ip_frame = validate_ip_threat_frame(ip_frame)

        # Merge OpenPhish AVANT rank_top_n_urls (cf. CDC "Data source integration rule") — les
        # entrées confirmées par 2 sources doivent pouvoir peser sur le cut top-N, pas seulement
        # sur l'affichage d'un item déjà retenu.
        url_frame = merge_openphish_urls(urlhaus_df, openphish_entries, observed_at=period_end)

        joined = (
            mttk.join_nvd_kev(cve_df, kev_df)
            if cve_df.height and kev_df.height
            else pl.DataFrame(schema={**_CVE_EMPTY_SCHEMA, "kev_date_added": pl.Datetime})
        )
        mean_time_to_kev = mttk.compute_mean_time_to_kev(joined)
        median_time_to_kev = mttk.compute_median_time_to_kev(joined)
        mttk_sample_size = joined.height
        kev_remediation_window_days = mttk.compute_mean_remediation_window_days(kev_df)

        ranked_cves = ranking.rank_top_n_cves(cve_df, n=10) if cve_df.height else cve_df
        ranked_ips = ranking.rank_top_n_ips(ip_frame, n=10) if ip_frame.height else ip_frame
        ranked_urls = ranking.rank_top_n_urls(url_frame, n=10) if url_frame.height else url_frame
        ranked_breaches = ranking.rank_top_n_breaches(hibp_entries, n=10)

        geo: dict[str, dict] = {}
        ip_list: list[str] = []
        if ranked_ips.height:
            ip_records = [
                FeodoIpRecord(**row) for row in ranked_ips.select(list(_FEODO_EMPTY_SCHEMA.keys())).to_dicts()
            ]
            ip_list = [r.ip_address for r in ip_records]
            geo_key = cache_key("geoloc", {"ips": sorted(ip_list)})
            geo_raw = await get_or_fetch(
                geo_key,
                lambda: _fetch_geo_wrapped(client, ip_records, settings.ip_api_batch_url),
                settings.cache_dir,
                settings.force_refresh,
            )
            geo = geo_raw[0] if geo_raw else {}

        # Enrichissement C2 (Shodan InternetDB, Spamhaus DROP/EDROP, GreyNoise) — uniquement sur
        # ip_list, déjà le top-N post rank_top_n_ips ci-dessus, jamais le feed complet (cf. CDC
        # "Data source integration rule"). Toujours appelés (même avec ip_list=[]) pour que
        # sources_status porte une entrée par source quel que soit le cas.
        shodan_data, shodan_status = await _run_shodan_source(
            client, settings, run_id, ip_list, base_path, storage_options
        )
        sources_status["shodan_internetdb"] = shodan_status
        sentry_breadcrumb_run_step("extract_shodan_internetdb", shodan_status)

        spamhaus_confirmed, spamhaus_status = await _run_spamhaus_source(
            client, settings, run_id, ip_list, base_path, storage_options
        )
        sources_status["spamhaus_drop"] = spamhaus_status
        sentry_breadcrumb_run_step("extract_spamhaus_drop", spamhaus_status)

        greynoise_data, greynoise_status = await _run_greynoise_source(
            client, settings, run_id, ip_list, base_path, storage_options
        )
        sources_status["greynoise"] = greynoise_status
        sentry_breadcrumb_run_step("extract_greynoise", greynoise_status)

        # BreachDirectory (cross-check secondaire, CDC Phase P5) — uniquement sur le domaine de
        # la breach la plus impactante du run (spotlight = ranked_breaches[0]), jamais sur toutes
        # les breaches (même principe "top-N déjà réduit" que Shodan/Spamhaus/GreyNoise ci-dessus).
        spotlight_domain = ranked_breaches[0].domain if ranked_breaches else None
        breachdirectory_count, breachdirectory_status = await _run_breachdirectory_source(
            client, settings, spotlight_domain
        )
        sources_status["breachdirectory"] = breachdirectory_status
        sentry_breadcrumb_run_step("extract_breachdirectory", breachdirectory_status)

        source_item_counts: dict[str, int] = {
            "nvd": cve_df.height,
            "kev": kev_df.height,
            "feodo": feodo_df.height,
            "urlhaus": urlhaus_df.height,
            "threatfox": len(threatfox_iocs),
            "openphish": len(openphish_entries),
            "shodan": len(shodan_data),
            "spamhaus": len(spamhaus_confirmed),
            "greynoise": len(greynoise_data),
            "hibp": len(hibp_entries),
        }
        extract_done_at = time.monotonic()

        previous_kpis = _kpis_from_manifest(manifest)
        report_kpis = kpis_module.compute_kpis(
            cve_df, kev_df, ip_frame, urlhaus_df, mean_time_to_kev, previous_kpis, cve_high_count, threatfox_iocs
        )

        top_cves = _build_top_cves(ranked_cves, kev_df)
        top_ips = _build_top_ips(ranked_ips, geo, shodan_data, spamhaus_confirmed, greynoise_data)
        c2_items = build_c2_items(top_ips)
        malicious_url_items = build_malicious_url_items(ranked_urls)
        breach_items = build_breach_items(ranked_breaches, breachdirectory_count)
        transform_done_at = time.monotonic()

        # load
        load_status = "success"
        s3_parquet_keys: dict[str, str] = {}
        period_end_str = period_end.strftime("%Y%m%d")
        for source, df in (("nvd", cve_df), ("kev", kev_df), ("feodo", feodo_df), ("urlhaus", urlhaus_df)):
            try:
                if df.height:
                    key = write_historical_parquet(df, source, period_end_str, run_id, base_path, storage_options)
                    s3_parquet_keys[source] = key
            except Exception:
                logger.exception("load: échec écriture parquet pour %s", source)
                load_status = "partial"

        pipeline_duration_seconds = time.monotonic() - started_at

        # "skipped*" (ThreatFox sans Auth-Key/Auth-Key invalide, lot 7 optionnel) ne dégrade
        # jamais le statut global — seul un "failed" (échec réel d'une source) le fait.
        report_status = (
            "success"
            if all(s == "ok" or s.startswith("skipped") for s in sources_status.values()) and load_status == "success"
            else "partial"
        )

        # PDF rendu AVANT la construction du payload JSON — sinon un échec PDF ne pourrait
        # mettre à jour `status` qu'après coup, sur un JSON déjà écrit sur disque (schéma
        # incohérent entre le fichier écrit et manifest.json/webhook, cf. §4 CDC "un seul
        # schéma de données à maintenir").
        s3_pdf_key = None
        try:
            local_pdf_path = Path(settings.local_data_dir) / f".tmp-pdf-{run_id}.pdf"
            local_pdf_path.parent.mkdir(parents=True, exist_ok=True)
            # Historique pour les sparklines PDF — lecture read-only de runs/index.json avant
            # append (finalize_manifest_and_index() lit/écrit ce même fichier plus loin dans le
            # run, aucun conflit d'ordre puisque cette lecture ne fait qu'ajouter le point courant
            # en mémoire, jamais d'écriture ici).
            history_entries = sorted(
                _read_json(base_path, storage_options, "runs/index.json") or [],
                key=lambda r: r.get("period_end", ""),
            )[-7:]
            pdf_context = build_pdf_context(
                run_id=run_id,
                period_start=period_start,
                period_end=period_end,
                generated_at=datetime.now(UTC),
                kpis=report_kpis,
                critical_items=top_cves,
                kev_df=kev_df,
                mttk_median_days=median_time_to_kev,
                mttk_sample_size=mttk_sample_size,
                kev_remediation_window_days=kev_remediation_window_days,
                feodo_df=ip_frame,
                c2_items=c2_items,
                malicious_url_items=malicious_url_items,
                breach_items=breach_items,
                pipeline_duration_seconds=pipeline_duration_seconds,
                sources_status=sources_status,
                is_cold_start=is_cold_start,
                history_entries=history_entries,
            )
            render_pdf(pdf_context, local_pdf_path)

            if storage_options is None:
                final_path = Path(base_path) / f"reports/report-{period_end_str}-{run_id}.pdf"
                final_path.parent.mkdir(parents=True, exist_ok=True)
                local_pdf_path.replace(final_path)
                s3_pdf_key = str(final_path)
            else:
                import fsspec

                fs = fsspec.filesystem("s3", **storage_options)
                remote_path = f"{base_path}/reports/report-{period_end_str}-{run_id}.pdf"
                fs.put(str(local_pdf_path), remote_path)
                local_pdf_path.unlink(missing_ok=True)
                s3_pdf_key = remote_path
        except Exception:
            logger.exception("load: échec rendu PDF, run marqué partial")
            report_status = "partial" if report_status == "success" else report_status

        payload = build_report_payload(
            run_id=run_id,
            period_start=period_start.isoformat(),
            period_end=period_end.isoformat(),
            status=report_status,
            kpis=report_kpis,
            top_cves=top_cves,
            top_ips=top_ips,
            pipeline_duration_seconds=pipeline_duration_seconds,
            sources_status=sources_status,
            c2_items=c2_items,
            malicious_url_items=malicious_url_items,
            is_cold_start=is_cold_start,
        )

        s3_json_key = None
        try:
            s3_json_key = write_report_json(payload, period_end_str, run_id, base_path, storage_options)
        except Exception:
            logger.exception("load: échec écriture JSON, run marqué failed")
            report_status = "failed"
            payload["status"] = "failed"

        load_done_at = time.monotonic()
        step_durations: dict[str, float] = {
            "extract": extract_done_at - started_at,
            "transform": transform_done_at - extract_done_at,
            "load": load_done_at - transform_done_at,
        }

        run_entry = finalize_manifest_and_index(
            run_id=run_id,
            period_start=period_start.isoformat(),
            period_end=period_end.isoformat(),
            status=report_status,
            sources_status=sources_status,
            kpis=report_kpis,
            s3_json_key=s3_json_key,
            s3_pdf_key=s3_pdf_key,
            s3_parquet_keys=s3_parquet_keys,
            pipeline_duration_seconds=pipeline_duration_seconds,
            base_path=base_path,
            storage_options=storage_options,
            source_item_counts=source_item_counts,
            step_durations=step_durations,
            skip_email=skip_email,
            github_run_id=github_run_id,
        )

        # publish_status() est le seul appel du pipeline sans try/except propre — une URL de
        # webhook malformée (ex. httpx.InvalidURL, ni TransportError ni HTTPStatusError) sortait
        # non catchée de cette fonction et faisait planter tout le run. Le webhook est une
        # notification best-effort, jamais un point de blocage (CDC §4 "continue en dégradé").
        try:
            webhook_status = await publish_status(
                client, settings.backend_webhook_url, settings.threat_report_internal_secret, run_entry
            )
        except Exception as exc:
            logger.exception("publish_webhook: échec inattendu, run non bloqué")
            try:
                import sentry_sdk

                sentry_sdk.capture_exception()
            except Exception:
                pass
            # Nom d'exception (ex. "failed:InvalidURL") plutôt que "failed" générique — seul
            # indice diagnosticable sans accès aux logs GitHub Actions/Sentry.
            webhook_status = f"failed:{type(exc).__name__}"
        sentry_breadcrumb_run_step("publish_webhook", webhook_status)
        _annotate_webhook_status(run_id, webhook_status, base_path, storage_options)

        log_run_summary(run_id, pipeline_duration_seconds, sources_status, report_kpis)

    return payload


def _annotate_webhook_status(run_id: str, webhook_status: str, base_path: str, storage_options: dict | None) -> None:
    """Patch runs/index.json a posteriori avec le résultat du webhook — finalize_manifest_and_index()
    doit s'exécuter avant publish_status() (le payload webhook est run_entry lui-même), donc ce
    statut ne peut être connu qu'après coup. Avant ce patch, un échec de webhook n'était visible
    nulle part (ni runs/index.json, ni manifest.json) — seulement dans un log brut ou une breadcrumb
    Sentry, tous deux inaccessibles sans logs GitHub Actions/Sentry. Best-effort : une erreur ici ne
    doit jamais faire échouer le run (le statut est déjà loggé/Sentry par ailleurs)."""
    try:
        index = _read_json(base_path, storage_options, "runs/index.json") or []
        for entry in index:
            if entry.get("run_id") == run_id:
                entry["webhook_status"] = webhook_status
                break
        _write_json(base_path, storage_options, "runs/index.json", index)
    except Exception:
        logger.exception("annotate: échec écriture webhook_status dans runs/index.json")


def _override_force_refresh(settings: Settings, force_refresh: bool) -> Settings:
    if not force_refresh:
        return settings
    import dataclasses

    return dataclasses.replace(settings, force_refresh=True)


def _kpis_from_manifest(manifest: dict | None):
    """Reconstruit un ReportKpis minimal depuis manifest.json — seuls cve_critical_count,
    kev_new_count, c2_active_count, malicious_url_count et threatfox_malware_families_count
    sont réellement consommés en aval (compute_kpis ne calcule de trend que sur ces champs),
    les autres champs sont des placeholders neutres."""
    if manifest is None:
        return None
    return kpis_module.ReportKpis(
        cve_critical_count=manifest.get("cve_critical_count", 0),
        cve_critical_trend_pct=None,
        cve_high_count=0,
        kev_new_count=manifest.get("kev_new_count", 0),
        kev_urgent_count=0,
        kev_ransomware_count=0,
        mean_time_to_kev_days=None,
        c2_active_count=manifest.get("c2_active_count", 0),
        malicious_url_count=manifest.get("malicious_url_count", 0),
        top_countries=[],
        top_vendors=[],
        cwe_distribution=[],
        threatfox_malware_families_count=manifest.get("threatfox_malware_families_count", 0),
    )


def finalize_manifest_and_index(
    run_id: str,
    period_start: str,
    period_end: str,
    status: str,
    sources_status: dict[str, str],
    kpis,
    s3_json_key: str | None,
    s3_pdf_key: str | None,
    s3_parquet_keys: dict[str, str],
    pipeline_duration_seconds: float,
    base_path: str,
    storage_options: dict | None,
    source_item_counts: dict[str, int] | None = None,
    step_durations: dict[str, float] | None = None,
    skip_email: bool = False,
    github_run_id: str | None = None,
) -> dict:
    run_entry = {
        "run_id": run_id,
        "period_start": period_start,
        "period_end": period_end,
        "status": status,
        "sources_status": sources_status,
        "source_item_counts": source_item_counts or {},
        "step_durations": step_durations or {},
        "cve_critical_count": kpis.cve_critical_count,
        "kev_new_count": kpis.kev_new_count,
        "c2_active_count": kpis.c2_active_count,
        "malicious_url_count": kpis.malicious_url_count,
        "threatfox_malware_families_count": kpis.threatfox_malware_families_count,
        "pipeline_duration_seconds": pipeline_duration_seconds,
        "s3_json_key": s3_json_key,
        "s3_pdf_key": s3_pdf_key,
        "s3_parquet_keys": s3_parquet_keys,
        "skip_email": skip_email,
        "github_run_id": github_run_id,
        "created_at": datetime.now(UTC).isoformat(),
    }

    index = _read_json(base_path, storage_options, "runs/index.json") or []
    index.append(run_entry)
    # Re-lecture juste avant écriture : réduit (sans l'éliminer, pas de verrou distribué sur S3 —
    # surdimensionné pour un cron hebdo + déclenchement manuel occasionnel, la concurrence réelle
    # est rare) la fenêtre de race d'un run concurrent qui écrirait runs/index.json entre notre
    # lecture initiale et notre écriture. Sans ça, un run qui termine pendant que celui-ci tourne
    # encore voit son entrée silencieusement écrasée (root cause plausible d'un run visible dans
    # l'historique mais 404 sur pdf-url, ou d'un run qui disparaît complètement de l'historique).
    latest = _read_json(base_path, storage_options, "runs/index.json") or []
    known_run_ids = {entry.get("run_id") for entry in index}
    for entry in latest:
        if entry.get("run_id") not in known_run_ids:
            index.append(entry)
            known_run_ids.add(entry.get("run_id"))
    _write_json(base_path, storage_options, "runs/index.json", index)

    if status in {"success", "partial"}:
        _write_json(base_path, storage_options, "manifest.json", run_entry)

    return run_entry


def main() -> None:
    from dotenv import load_dotenv

    load_dotenv()
    # ponytail: root à WARNING pour couper le bruit des libs tierces (httpx logue chaque
    # requête HTTP en INFO, fontTools.subset logue chaque étape du PDF) — seul le pipeline
    # (logger "beesint_threat_report") reste en INFO. Étendre si un autre lib devient bruyante.
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    logging.getLogger("beesint_threat_report").setLevel(logging.INFO)

    parser = argparse.ArgumentParser()
    parser.add_argument("--force-refresh", action="store_true")
    parser.add_argument("--skip-email", action="store_true")
    args = parser.parse_args()
    asyncio.run(run(force_refresh=args.force_refresh, skip_email=args.skip_email))


if __name__ == "__main__":
    main()
