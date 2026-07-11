from __future__ import annotations

import logging

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.TransportError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return status == 429 or status >= 500
    return False


def _build_headers(secret: str | None) -> dict[str, str]:
    return {"X-Threat-Report-Secret": secret} if secret else {}


@retry(
    reraise=True,
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    retry=retry_if_exception(_is_retryable),
)
async def _post_status(client: httpx.AsyncClient, url: str, headers: dict, payload: dict) -> None:
    response = await client.post(url, json=payload, headers=headers)
    response.raise_for_status()


async def publish_status(
    client: httpx.AsyncClient,
    webhook_url: str | None,
    secret: str | None,
    payload: dict,
) -> str:
    if webhook_url is None:
        logger.info(
            "webhook: dry-run (BACKEND_WEBHOOK_URL absent) - run %s status=%s",
            payload.get("run_id"),
            payload.get("status"),
        )
        return "dry_run"

    try:
        await _post_status(client, webhook_url, _build_headers(secret), payload)
        return "sent"
    except (httpx.TransportError, httpx.HTTPStatusError) as exc:
        logger.error("webhook: échec définitif après retries: %s", exc)
        try:
            import sentry_sdk

            sentry_sdk.capture_exception(exc)
        except Exception:
            pass
        # Détail diagnosticable depuis runs/index.json seul (pas de logs GH Actions/Sentry
        # nécessaires) : code HTTP pour un rejet serveur, nom d'exception pour un échec réseau.
        if isinstance(exc, httpx.HTTPStatusError):
            return f"failed:{exc.response.status_code}"
        return f"failed:{type(exc).__name__}"
