from __future__ import annotations

import logging

from beesint_threat_report.validate.schemas import (
    FeodoIpRecord,
    KevEntry,
    NvdCveRecord,
    UrlhausEntry,
)

logger = logging.getLogger(__name__)


def _dedup_by_key(records: list, key_fn, keep_latest_fn=None) -> list:
    kept: dict = {}
    discarded = 0
    for record in records:
        key = key_fn(record)
        if key is None:
            discarded += 1
            continue
        existing = kept.get(key)
        if existing is None:
            kept[key] = record
        elif keep_latest_fn is not None and keep_latest_fn(record) > keep_latest_fn(existing):
            kept[key] = record
    if discarded:
        logger.warning("dedup: %s enregistrement(s) écarté(s) pour clé manquante", discarded)
    return list(kept.values())


def dedup_cves(records: list[NvdCveRecord]) -> list[NvdCveRecord]:
    return _dedup_by_key(records, key_fn=lambda r: r.cve_id, keep_latest_fn=lambda r: r.last_modified_date)


def dedup_kev(records: list[KevEntry]) -> list[KevEntry]:
    return _dedup_by_key(records, key_fn=lambda r: r.cve_id)


def dedup_feodo(records: list[FeodoIpRecord]) -> list[FeodoIpRecord]:
    return _dedup_by_key(records, key_fn=lambda r: r.ip_address)


def dedup_urlhaus(records: list[UrlhausEntry]) -> list[UrlhausEntry]:
    return _dedup_by_key(records, key_fn=lambda r: r.url)
