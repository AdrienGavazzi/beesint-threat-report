from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def _to_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class NvdCveRecord(BaseModel):
    model_config = ConfigDict(frozen=True)
    cve_id: str
    published_date: datetime
    last_modified_date: datetime
    cvss_v3_score: float | None = None
    cvss_v3_severity: str | None = None
    description: str
    cwe_ids: list[str] = []
    vendor: str | None = None
    references: list[str] = []

    @field_validator("cve_id")
    @classmethod
    def _validate_cve_id(cls, value: str) -> str:
        if not _CVE_ID_RE.match(value):
            raise ValueError(f"cve_id invalide: {value!r}")
        return value

    @field_validator("published_date", "last_modified_date")
    @classmethod
    def _force_utc(cls, value: datetime) -> datetime:
        return _to_utc(value)


class KevEntry(BaseModel):
    model_config = ConfigDict(frozen=True)
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: datetime
    short_description: str
    required_action: str
    due_date: datetime
    known_ransomware_campaign_use: str  # "Known" | "Unknown"

    @field_validator("cve_id")
    @classmethod
    def _validate_cve_id(cls, value: str) -> str:
        if not _CVE_ID_RE.match(value):
            raise ValueError(f"cve_id invalide: {value!r}")
        return value

    @field_validator("date_added", "due_date")
    @classmethod
    def _force_utc(cls, value: datetime) -> datetime:
        return _to_utc(value)


class BreachEntry(BaseModel):
    """Une entrée du catalogue HIBP `/api/v3/breaches` — même forme que KevEntry (cf. CDC
    Phase P5 "Breaches This Week")."""

    model_config = ConfigDict(frozen=True)
    name: str
    title: str
    domain: str = ""
    breach_date: datetime
    added_date: datetime
    pwn_count: int = 0
    data_classes: list[str] = []
    is_verified: bool = False
    is_sensitive: bool = False
    description: str = ""

    @field_validator("breach_date", "added_date")
    @classmethod
    def _force_utc(cls, value: datetime) -> datetime:
        return _to_utc(value)


class FeodoIpRecord(BaseModel):
    model_config = ConfigDict(frozen=True)
    ip_address: str
    port: int | None = None
    status: str  # "online" | "offline"
    malware: str
    first_seen: datetime
    last_online: datetime | None = None
    country: str | None = None
    as_number: int | None = None
    as_name: str | None = None

    @field_validator("ip_address")
    @classmethod
    def _validate_ip(cls, value: str) -> str:
        ipaddress.ip_address(value)  # raises ValueError si malformé
        return value

    @field_validator("first_seen", "last_online")
    @classmethod
    def _force_utc(cls, value: datetime | None) -> datetime | None:
        return _to_utc(value) if value is not None else None


class UrlhausEntry(BaseModel):
    model_config = ConfigDict(frozen=True)
    url: str
    url_status: str  # "online" | "offline"
    date_added: datetime
    threat: str
    tags: list[str] = []
    host: str
    reporter: str | None = None

    @field_validator("date_added")
    @classmethod
    def _force_utc(cls, value: datetime) -> datetime:
        return _to_utc(value)


class ShodanInternetDbRecord(BaseModel):
    """Un enregistrement par IP (pas de endpoint batch sur le tier gratuit InternetDB) —
    l'IP 404/non-indexée n'atteint jamais validate_batch, filtrée en amont dans l'extracteur."""

    model_config = ConfigDict(frozen=True)
    ip: str
    ports: list[int] = []
    vulns: list[str] = []
    tags: list[str] = []

    @field_validator("ip")
    @classmethod
    def _validate_ip(cls, value: str) -> str:
        ipaddress.ip_address(value)  # raises ValueError si malformé
        return value


class SpamhausRange(BaseModel):
    """Une ligne CIDR du flux texte DROP/EDROP — validée pour quarantiner une ligne malformée
    sans faire planter le parsing du reste du flux (~milliers de lignes)."""

    model_config = ConfigDict(frozen=True)
    cidr: str

    @field_validator("cidr")
    @classmethod
    def _validate_cidr(cls, value: str) -> str:
        ipaddress.ip_network(value, strict=False)  # raises ValueError si malformé
        return value


class GreyNoiseClassification(BaseModel):
    """`classification` reste la valeur brute renvoyée par GreyNoise (pas de champ Literal
    contraint) — leur doc publique liste benign/malicious/unknown (+ suspicious sur d'autres
    tiers), pas garanti figé, cf. commentaire greynoise.py sur le sens réel de "benign"."""

    model_config = ConfigDict(frozen=True)
    ip: str
    classification: str

    @field_validator("ip")
    @classmethod
    def _validate_ip(cls, value: str) -> str:
        ipaddress.ip_address(value)
        return value


class OpenPhishEntry(BaseModel):
    """Remplace PhishTankEntry (inscriptions PhishTank fermées, plus de clé API obtenable). Le
    flux public OpenPhish (feed.txt) est une simple liste d'URLs sans métadonnées par entrée
    (pas de submission_time/verified/target) — d'où le schéma minimal ici."""

    model_config = ConfigDict(frozen=True)
    url: str


class ThreatFoxIoc(BaseModel):
    model_config = ConfigDict(frozen=True)
    ioc_id: str
    ioc_type: str  # valeurs API réelles ("ip:port", "domain", "md5_hash", "sha256_hash", "url", ...)
    ioc_value: str
    threat_type: str
    malware: str
    malware_printable: str
    confidence_level: int
    first_seen: datetime
    last_seen: datetime | None = None
    reporter: str
    tags: list[str] = []

    @field_validator("first_seen", "last_seen")
    @classmethod
    def _force_utc(cls, value: datetime | None) -> datetime | None:
        return _to_utc(value) if value is not None else None


def validate_batch(
    raw_items: list[dict], model: type[BaseModel], source: str, run_id: str
) -> tuple[list[BaseModel], list[dict]]:
    """Valide chaque item individuellement. Ne lève jamais : un item invalide est
    quarantiné (retourné brut dans rejected), le reste continue. `source`/`run_id`
    sont pour la signature de l'appelant (orchestrate.py construit la clé S3
    quarantine/{source}/{run_id}/{index}.json) — non utilisés ici, validate/ ne
    connaît pas S3."""
    valid: list[BaseModel] = []
    rejected: list[dict] = []
    for item in raw_items:
        try:
            valid.append(model.model_validate(item))
        except ValidationError:
            rejected.append(item)
    return valid, rejected
