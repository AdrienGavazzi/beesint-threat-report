from __future__ import annotations

import ipaddress

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.TransportError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return status == 429 or status >= 500
    return False


_spamhaus_retry = retry(
    reraise=True,
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=1, max=30),
    retry=retry_if_exception(_is_retryable),
)


def _parse_drop_txt(text: str) -> list[dict]:
    """Une ligne par CIDR : `1.2.3.0/24 ; SBL12345` (commentaires `;` — et `#` par précaution,
    les deux formes existent selon les flux abuse-style). Retourne list[dict] (pas list[str])
    pour rester compatible avec le contrat list[dict] de cache.get_or_fetch/validate_batch,
    même forme que les autres extracteurs."""
    ranges: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        cidr = line.split(";")[0].strip()
        if cidr:
            ranges.append({"cidr": cidr})
    return ranges


@_spamhaus_retry
async def _fetch_list(client: httpx.AsyncClient, url: str) -> str:
    response = await client.get(url)
    response.raise_for_status()
    return response.text


async def fetch_spamhaus_ranges(
    client: httpx.AsyncClient,
    drop_url: str = "https://www.spamhaus.org/drop/drop.txt",
    edrop_url: str = "https://www.spamhaus.org/drop/edrop.txt",
) -> list[dict]:
    """Télécharge DROP + EDROP une seule fois par run (pas par IP, contrairement à Shodan) —
    le matching IP-dans-CIDR se fait ensuite via le module stdlib ipaddress."""
    ranges: list[dict] = []
    for url in (drop_url, edrop_url):
        text = await _fetch_list(client, url)
        ranges.extend(_parse_drop_txt(text))
    return ranges


def match_ips_against_ranges(ips: list[str], cidr_ranges: list[str]) -> set[str]:
    """ponytail: O(len(ips) * len(ranges)) — DROP+EDROP font quelques milliers de lignes et ips
    est déjà borné au top-N (10 par rank_top_n_ips), largement assez rapide pour un run
    hebdomadaire. Pas d'interval-tree/index trié, à ajouter si ips cesse d'être top-N borné."""
    networks = []
    for cidr in cidr_ranges:
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue  # ligne malformée déjà censée être filtrée par validate_batch en amont

    matched: set[str] = set()
    for ip_str in ips:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if any(ip in net for net in networks):
            matched.add(ip_str)
    return matched
