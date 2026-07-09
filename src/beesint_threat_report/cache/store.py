from __future__ import annotations

import hashlib
import json
import logging
import time
from collections.abc import Awaitable, Callable
from pathlib import Path

logger = logging.getLogger(__name__)


def cache_key(source: str, params: dict) -> str:
    digest = hashlib.sha256(json.dumps(params, sort_keys=True, default=str).encode()).hexdigest()
    return f"{source}-{digest[:16]}"


async def get_or_fetch(
    key: str,
    fetch_fn: Callable[[], Awaitable[list[dict]]],
    cache_dir: Path,
    force_refresh: bool,
    ttl_seconds: int | None = None,
) -> list[dict]:
    cache_path = cache_dir / f"{key}.json"

    if not force_refresh:
        if cache_path.exists() and not _is_expired(cache_path, ttl_seconds):
            cached = _read_cache_file(cache_path)
            if cached is not None:
                return cached

    payload = await fetch_fn()
    _write_cache_file(cache_path, payload)
    return payload


def _read_cache_file(path: Path) -> list[dict] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        logger.warning("cache: fichier corrompu ou illisible, traité comme miss: %s", path)
        return None


def _write_cache_file(path: Path, payload: list[dict]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")
    except OSError as exc:
        logger.warning("cache: écriture échouée, continue sans cache écrit: %s (%s)", path, exc)


def _is_expired(path: Path, ttl_seconds: int | None) -> bool:
    if ttl_seconds is None:
        return False
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return True
    return (time.time() - mtime) > ttl_seconds
