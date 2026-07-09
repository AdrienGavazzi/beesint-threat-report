from __future__ import annotations

import logging
from datetime import datetime

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)

_NVD_RESULTS_PER_PAGE = 2000


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.TransportError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return status == 429 or status >= 500
    return False


_nvd_retry = retry(
    reraise=True,
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=1, max=30),
    retry=retry_if_exception(_is_retryable),
)


def _format_nvd_datetime(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def _paginate_params(start_index: int, results_per_page: int) -> dict[str, str | int]:
    return {"startIndex": start_index, "resultsPerPage": results_per_page}


def _build_headers(api_key: str | None) -> dict[str, str]:
    return {"apiKey": api_key} if api_key else {}


def _extract_vendor(cve: dict) -> str | None:
    for config in cve.get("configurations", []) or []:
        for node in config.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                criteria = match.get("criteria")
                if not criteria:
                    continue
                parts = criteria.split(":")
                if len(parts) > 3 and parts[3]:
                    return parts[3]
    return None


def _extract_description(cve: dict) -> str:
    for desc in cve.get("descriptions", []) or []:
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""


def _extract_cwe_ids(cve: dict) -> list[str]:
    cwe_ids: list[str] = []
    for weakness in cve.get("weaknesses", []) or []:
        for desc in weakness.get("description", []) or []:
            if desc.get("lang") == "en" and desc.get("value"):
                cwe_ids.append(desc["value"])
    return cwe_ids


def _extract_cvss(cve: dict) -> tuple[float | None, str | None]:
    metrics = cve.get("metrics", {}) or {}
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            return data.get("baseScore"), data.get("baseSeverity")
    return None, None


def _map_cve_item(item: dict) -> dict:
    cve = item["cve"]
    score, severity = _extract_cvss(cve)
    return {
        "cve_id": cve["id"],
        "published_date": cve["published"],
        "last_modified_date": cve["lastModified"],
        "cvss_v3_score": score,
        "cvss_v3_severity": severity,
        "description": _extract_description(cve),
        "cwe_ids": _extract_cwe_ids(cve),
        "vendor": _extract_vendor(cve),
        "references": [ref.get("url") for ref in cve.get("references", []) if ref.get("url")],
    }


@_nvd_retry
async def fetch_critical_cves(
    client: httpx.AsyncClient,
    period_start: datetime,
    period_end: datetime,
    api_key: str | None,
    max_results: int,
    base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0",
) -> list[dict]:
    """Pagine sur la fenêtre [period_start, period_end], filtre cvssV3Severity=CRITICAL.
    Retourne des dicts au format canonique (champs NvdCveRecord), pas encore validés
    Pydantic — la validation se fait via validate.schemas.validate_batch (appelée par
    orchestrate.py)."""
    headers = _build_headers(api_key)
    base_params = {
        "pubStartDate": _format_nvd_datetime(period_start),
        "pubEndDate": _format_nvd_datetime(period_end),
        "cvssV3Severity": "CRITICAL",
    }

    collected: list[dict] = []
    start_index = 0
    while True:
        results_per_page = min(_NVD_RESULTS_PER_PAGE, max_results - len(collected))
        if results_per_page <= 0:
            break
        params = {**base_params, **_paginate_params(start_index, results_per_page)}
        response = await client.get(base_url, params=params, headers=headers)
        response.raise_for_status()
        payload = response.json()

        for vuln in payload.get("vulnerabilities", []):
            collected.append(_map_cve_item(vuln))
            if len(collected) >= max_results:
                break

        total_results = payload.get("totalResults", 0)
        start_index += results_per_page
        if start_index >= total_results or len(collected) >= max_results:
            break

    if len(collected) >= max_results and start_index < payload.get("totalResults", 0):
        logger.warning(
            "NVD: cap MAX_RESULTS=%s atteint, résultats tronqués (totalResults=%s)",
            max_results,
            payload.get("totalResults"),
        )

    return collected[:max_results]


@_nvd_retry
async def count_high_severity_cves(
    client: httpx.AsyncClient,
    period_start: datetime,
    period_end: datetime,
    api_key: str | None,
    base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0",
) -> int:
    headers = _build_headers(api_key)
    params = {
        "pubStartDate": _format_nvd_datetime(period_start),
        "pubEndDate": _format_nvd_datetime(period_end),
        "cvssV3Severity": "HIGH",
        "resultsPerPage": 1,
    }
    response = await client.get(base_url, params=params, headers=headers)
    response.raise_for_status()
    return response.json().get("totalResults", 0)
