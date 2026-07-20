from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

# botocore >=1.36 ajoute par défaut un checksum qui force l'upload en "aws-chunked" —
# non supporté par Oracle Object Storage ("AWS chunked encoding not supported", vérifié
# empiriquement) ni par moto (utilisé en test). setdefault() : ne casse rien si déjà fixé.
os.environ.setdefault("AWS_REQUEST_CHECKSUM_CALCULATION", "when_required")


@dataclass(frozen=True)
class Settings:
    # Fenêtre & run
    report_window_days: int = 7
    max_results_nvd: int = 2000
    max_results_kev: int = 5000

    # Sources
    nvd_api_key: str | None = None
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    kev_feed_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    feodo_feed_url: str = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    urlhaus_feed_url: str = "https://urlhaus.abuse.ch/downloads/json_online/"
    ip_api_batch_url: str = "http://ip-api.com/batch"
    threatfox_auth_key: str | None = None  # optionnel (Lot 7) — étape sautée si absente
    threatfox_base_url: str = "https://threatfox-api.abuse.ch/api/v1/"
    shodan_internetdb_base_url: str = "https://internetdb.shodan.io"  # gratuit, sans clé
    spamhaus_drop_url: str = "https://www.spamhaus.org/drop/drop.txt"
    spamhaus_edrop_url: str = "https://www.spamhaus.org/drop/edrop.txt"
    greynoise_api_key: str | None = None  # optionnel — étape sautée si absente
    greynoise_base_url: str = "https://api.greynoise.io/v3/community"
    # PhishTank retiré (inscriptions fermées, plus de clé API obtenable, cf. décision produit) —
    # remplacé par OpenPhish : flux public gratuit, aucune clé, même usage (URLs phishing).
    openphish_feed_url: str = "https://openphish.com/feed.txt"
    hibp_breaches_url: str = "https://haveibeenpwned.com/api/v3/breaches"  # gratuit, sans clé
    rapidapi_key: str | None = None  # optionnel (BreachDirectory cross-check) — étape sautée si absente
    epss_base_url: str = "https://api.first.org/data/v1/epss"  # gratuit, sans clé
    # ransomware.live : la doc publique (ransomware.live/apidocs) décrit une API REST
    # api.ransomware.live/v2/* qui répond 404 en pratique (vérifié) — les vraies données sont ces
    # 2 dumps JSON statiques complets sur un sous-domaine différent, CORS ouvert, sans clé.
    ransomware_live_posts_url: str = "https://data.ransomware.live/posts.json"
    ransomware_live_groups_url: str = "https://data.ransomware.live/groups.json"

    # Stockage
    storage_backend: str = "local"  # "local" | "s3"
    local_data_dir: Path = Path(".data")
    s3_bucket: str | None = None
    s3_endpoint_url: str | None = None
    s3_access_key: str | None = None
    s3_secret_key: str | None = None

    # Cache
    cache_dir: Path = Path(".cache")
    force_refresh: bool = False

    # Publish
    threat_report_internal_secret: str | None = None
    backend_webhook_url: str | None = None  # None => dry-run stub (Lot 6 pas encore là)

    # Observabilité
    sentry_dsn: str | None = None
    environment: str = "development"

    # Timezone : UTC unique, jamais de zone locale — voir CDC § 12
    tz: str = "UTC"


def _get_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _get_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name}: valeur non castable en int: {raw!r}") from exc


def _get_secret(name: str) -> str | None:
    # .strip() : un secret GitHub Actions collé avec un `\n` de fin de ligne devient un header
    # HTTP invalide ("Illegal header value b'...\n'") dans les extracteurs qui le posent tel
    # quel (greynoise.py, breachdirectory.py) — jamais fiable de compter sur une valeur propre.
    raw = os.environ.get(name)
    return raw.strip() or None if raw else None


def load_settings() -> Settings:
    storage_backend = os.environ.get("STORAGE_BACKEND", "local")

    settings = Settings(
        report_window_days=_get_int("REPORT_WINDOW_DAYS", 7),
        max_results_nvd=_get_int("MAX_RESULTS_NVD", 2000),
        max_results_kev=_get_int("MAX_RESULTS_KEV", 5000),
        nvd_api_key=_get_secret("NVD_API_KEY"),
        threatfox_auth_key=_get_secret("THREATFOX_AUTH_KEY"),
        greynoise_api_key=_get_secret("GREYNOISE_API_KEY"),
        rapidapi_key=_get_secret("RAPIDAPI_KEY"),
        storage_backend=storage_backend,
        s3_bucket=os.environ.get("ORACLE_S3_BUCKET") or None,
        s3_endpoint_url=os.environ.get("ORACLE_S3_ENDPOINT") or None,
        s3_access_key=os.environ.get("ORACLE_S3_ACCESS_KEY") or None,
        s3_secret_key=os.environ.get("ORACLE_S3_SECRET_KEY") or None,
        force_refresh=_get_bool("FORCE_REFRESH", False),
        threat_report_internal_secret=os.environ.get("THREAT_REPORT_INTERNAL_SECRET") or None,
        backend_webhook_url=os.environ.get("BACKEND_WEBHOOK_URL") or None,
        sentry_dsn=os.environ.get("SENTRY_DSN_THREAT_REPORT") or None,
        environment=os.environ.get("ENVIRONMENT", "development"),
    )

    if settings.storage_backend == "s3":
        missing = [
            name
            for name, value in (
                ("ORACLE_S3_ACCESS_KEY", settings.s3_access_key),
                ("ORACLE_S3_SECRET_KEY", settings.s3_secret_key),
                ("ORACLE_S3_ENDPOINT", settings.s3_endpoint_url),
                ("ORACLE_S3_BUCKET", settings.s3_bucket),
            )
            if not value
        ]
        if missing:
            raise ValueError(
                f"STORAGE_BACKEND=s3 requiert les variables d'environnement suivantes, manquantes: {', '.join(missing)}"
            )

    return settings


def resolve_base_path(settings: Settings) -> str:
    if settings.storage_backend == "s3":
        return f"s3://{settings.s3_bucket}"
    return str(settings.local_data_dir)


def _extract_region_from_endpoint(endpoint_url: str) -> str | None:
    # endpoint S3-compatible Oracle : https://{namespace}.compat.objectstorage.{region}.oraclecloud.com
    # SigV4 exige une région explicite pour signer hors home region — évite une variable
    # d'env dédiée puisque la région est déjà encodée dans l'endpoint.
    host = urlparse(endpoint_url).hostname or ""
    parts = host.split(".")
    if "objectstorage" in parts:
        idx = parts.index("objectstorage")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return None


def resolve_storage_options(settings: Settings) -> dict | None:
    if settings.storage_backend != "s3":
        return None
    # endpoint_url DOIT être top-level (pas dans client_kwargs) — sinon aiobotocore
    # échoue la signature SigV4 ("secret key required... region must be specified"),
    # vérifié empiriquement contre un vrai bucket Oracle. region_name, lui, va dans
    # client_kwargs (accepté nulle part ailleurs par s3fs).
    client_kwargs = {}
    region = _extract_region_from_endpoint(settings.s3_endpoint_url or "")
    if region:
        client_kwargs["region_name"] = region
    return {
        "key": settings.s3_access_key,
        "secret": settings.s3_secret_key,
        "endpoint_url": settings.s3_endpoint_url,
        "client_kwargs": client_kwargs,
        # botocore >=1.36 (confirmé installé : 1.41.5) défaut à un transfer-encoding
        # chunked + trailing checksum sur PutObject qu'Oracle Cloud Object Storage (endpoint
        # S3-compatible) rejette ("AWS chunked encoding is not supported" / SignatureDoesNotMatch,
        # vérifié empiriquement contre un vrai bucket Oracle). "when_required" retombe sur le
        # comportement pré-1.36 (pas de checksum trailer, pas de chunked encoding forcé), seule
        # option compatible avec ce endpoint. config_kwargs est le paramètre s3fs qui les passe
        # tel quel à botocore.config.Config(**config_kwargs).
        "config_kwargs": {
            "request_checksum_calculation": "when_required",
            "response_checksum_validation": "when_required",
        },
    }
