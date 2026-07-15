from __future__ import annotations

import math
from datetime import datetime

import polars as pl

from beesint_threat_report.load.countries import country_name
from beesint_threat_report.load.cwe_names import cwe_name
from beesint_threat_report.load.world_map_path import WORLD_LANDMASS_PATH_D
from beesint_threat_report.transform.kpis import ReportKpis

_TOP_N_COUNTRIES = 10
_URL_TRUNCATE_LEN = 80

_SOURCES = [
    {
        "name": "NVD (National Vulnerability Database)",
        "url": "https://nvd.nist.gov/",
        "note": "Domaine public — NIST.",
    },
    {
        "name": "CISA Known Exploited Vulnerabilities (KEV)",
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "note": "Domaine public — CISA.",
    },
    {
        "name": "abuse.ch FeodoTracker",
        "url": "https://feodotracker.abuse.ch/",
        "note": "Data kindly provided by abuse.ch",
    },
    {
        "name": "abuse.ch URLhaus",
        "url": "https://urlhaus.abuse.ch/",
        "note": "Data kindly provided by abuse.ch",
    },
    {
        "name": "abuse.ch ThreatFox",
        "url": "https://threatfox.abuse.ch/",
        "note": "Data kindly provided by abuse.ch",
    },
    {
        "name": "ip-api.com",
        "url": "https://ip-api.com/",
        "note": "Géolocalisation IP, usage non-commercial.",
    },
    {
        "name": "Shodan InternetDB",
        "url": "https://internetdb.shodan.io/",
        "note": "Domaine public — gratuit, sans clé API.",
    },
    {
        "name": "Spamhaus DROP/EDROP",
        "url": "https://www.spamhaus.org/drop/",
        "note": "Listes CIDR publiques — usage non-commercial.",
    },
    {
        "name": "GreyNoise Community API",
        "url": "https://viz.greynoise.io/",
        "note": "Tier gratuit, clé API requise — classification IP.",
    },
    {
        "name": "PhishTank",
        "url": "https://www.phishtank.com/",
        "note": "Opéré par Cisco Talos — clé API requise pour le flux bulk.",
    },
]


_SPARKLINE_COLOR = "#38BDF8"  # --color-primary-light — visible sur fond sombre à petite taille
_DEGRADED_STATUS_PREFIXES = ("failed",)

# Couleurs SVG hardcodées (copiées des tokens report.css) plutôt que var(--...) : ces chaînes
# sont générées en Python pur, hors du pipeline CSS, même choix que _SPARKLINE_COLOR ci-dessus.
_TEXT_BODY_COLOR = "#E2E8F0"
_TEXT_MUTED_COLOR = "#6B849E"
_GRID_COLOR = "#2A2D3A"  # --color-border
_MAP_DOT_COLOR = "#F59E0B"  # --color-accent-gold
_DONUT_CRITICAL_COLOR = "#EF4444"  # --color-error
_DONUT_HIGH_COLOR = "#F59E0B"  # --color-warning
_HISTOGRAM_COLOR = "#0EA5E9"  # --color-primary
_HISTOGRAM_MIN_ITEMS = 6  # sous ce seuil, un histogramme par bin serait aussi peu lisible que
# les bar-charts count=1 déjà bannis ailleurs (vendors/CWE) — cf. philosophie du fichier.
# Palette catégorielle fixe pour le line chart CVE/KEV/C2 (3 séries, un seul axe partagé —
# les 3 KPI sont des comptages de même ordre de grandeur, contrairement à malicious_url_count
# qui reste sur son propre sparkline). Violet choisi pour C2 : ni error ni warning, pour ne pas
# entrer en collision avec la sémantique "statut" déjà portée par ces deux couleurs ailleurs.
_LINE_SERIES_COLORS = {"cve": "#0EA5E9", "kev": "#F59E0B", "c2": "#A78BFA"}
_LINE_MIN_POINTS = 2

# "Poignée" d'IP avec des ports Shodan avant d'afficher le chip-list — sur un pool d'au plus 10
# IP top-N (rank_top_n_ips), exiger _HISTOGRAM_MIN_ITEMS (6) serait quasi jamais atteint vu la
# couverture partielle de Shodan InternetDB (tier gratuit, IP non indexées fréquentes). 3 reste
# "plusieurs IP réelles", pas un chiffre isolé (même discipline que _HISTOGRAM_MIN_ITEMS).
_PORT_BREAKDOWN_MIN_IPS = 3


def _fmt_date(value: datetime) -> str:
    return value.strftime("%d %B %Y")


def _build_sparkline_svg(
    values: list[float], width: int = 64, height: int = 20, color: str = _SPARKLINE_COLOR
) -> str | None:
    """SVG polyline pur Python (pas de lib de chart) — None si pas assez de points pour être
    lisible, jamais d'exception sur une série vide/plate (cf. philosophie "continue en dégradé")."""
    if len(values) < 2:
        return None
    lo, hi = min(values), max(values)
    span = (hi - lo) or 1  # série plate (toutes valeurs égales) — évite une division par zéro
    step = width / (len(values) - 1)
    points = " ".join(f"{i * step:.1f},{height - ((v - lo) / span * height):.1f}" for i, v in enumerate(values))
    return (
        f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" class="sparkline">'
        f'<polyline points="{points}" fill="none" stroke="{color}" stroke-width="1.5" '
        f'stroke-linecap="round" stroke-linejoin="round"/></svg>'
    )


def _build_world_map_svg(items: list[dict], width: int = 480, height: int = 220) -> str | None:
    """Scatter équirectangulaire pur SVG (pas de tuiles/basemap : aucun appel réseau depuis le
    rendu PDF, cf. philosophie "continue en dégradé" — un run ETL ne doit jamais dépendre de la
    disponibilité d'un service tiers juste pour dessiner une carte)."""
    points = [
        (item["lon"], item["lat"]) for item in items if item.get("lat") is not None and item.get("lon") is not None
    ]
    if not points:
        return None

    def _project(lon: float, lat: float) -> tuple[float, float]:
        return (lon + 180) / 360 * width, (90 - lat) / 180 * height

    graticule = []
    for lon in range(-180, 181, 30):
        x, _ = _project(lon, 0)
        graticule.append(
            f'<line x1="{x:.1f}" y1="0" x2="{x:.1f}" y2="{height}" stroke="{_GRID_COLOR}" stroke-width="0.5"/>'
        )
    for lat in range(-60, 91, 30):
        _, y = _project(0, lat)
        graticule.append(
            f'<line x1="0" y1="{y:.1f}" x2="{width}" y2="{y:.1f}" stroke="{_GRID_COLOR}" stroke-width="0.5"/>'
        )

    dots = []
    for lon, lat in points:
        x, y = _project(lon, lat)
        dots.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4" fill="{_MAP_DOT_COLOR}" fill-opacity="0.9" '
            f'stroke="{_MAP_DOT_COLOR}" stroke-opacity="0.25" stroke-width="5"/>'
        )

    # fill volontairement _GRID_COLOR (pas --color-bg-elevated) : le SVG est affiché dans
    # .map-frame dont le fond EST déjà --color-bg-elevated — un fill de la même couleur s'y
    # fond entièrement quel que soit le fill-opacity (vérifié empiriquement, silhouette
    # invisible au rendu). _GRID_COLOR est plus clair que le fond du cadre, donc visible dessus.
    landmass = (
        f'<path d="{WORLD_LANDMASS_PATH_D}" fill="{_GRID_COLOR}" fill-opacity="0.45" '
        f'stroke="{_GRID_COLOR}" stroke-width="0.5"/>'
    )

    return (
        f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" class="world-map">'
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="none" stroke="{_GRID_COLOR}" stroke-width="1"/>'
        + landmass
        + "".join(graticule)
        + "".join(dots)
        + "</svg>"
    )


def _build_severity_donut_svg(critical_count: int, high_count: int, size: int = 130, stroke: int = 16) -> str | None:
    total = critical_count + high_count
    if total <= 0:
        return None
    radius = (size - stroke) / 2
    circumference = 2 * math.pi * radius
    critical_len = circumference * (critical_count / total)
    cx = cy = size / 2

    segments = (
        f'<circle cx="{cx}" cy="{cy}" r="{radius}" fill="none" stroke="{_DONUT_CRITICAL_COLOR}" '
        f'stroke-width="{stroke}" stroke-dasharray="{critical_len:.1f} {circumference:.1f}" '
        f'transform="rotate(-90 {cx} {cy})"/>'
    )
    if high_count > 0:
        high_len = circumference - critical_len
        segments += (
            f'<circle cx="{cx}" cy="{cy}" r="{radius}" fill="none" stroke="{_DONUT_HIGH_COLOR}" '
            f'stroke-width="{stroke}" stroke-dasharray="{high_len:.1f} {circumference:.1f}" '
            f'stroke-dashoffset="-{critical_len:.1f}" transform="rotate(-90 {cx} {cy})"/>'
        )

    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" class="severity-donut">'
        f"{segments}"
        f'<text x="{cx}" y="{cy - 3}" text-anchor="middle" fill="{_TEXT_BODY_COLOR}" '
        f'font-family="JetBrains Mono, monospace" font-size="22" font-weight="700">{total}</text>'
        f'<text x="{cx}" y="{cy + 15}" text-anchor="middle" fill="{_TEXT_MUTED_COLOR}" '
        f'font-family="JetBrains Mono, monospace" font-size="8" letter-spacing="1">CVEs</text>'
        f"</svg>"
    )


def _build_cvss_histogram_svg(
    critical_items: list[dict], width: int = 280, height: int = 110, bins: int = 4
) -> str | None:
    """Distribution des scores CVSS des CVE critiques de la semaine — uniquement sur des scores
    réels (pas de fabrication de données). Sous _HISTOGRAM_MIN_ITEMS, retourne None plutôt que de
    reproduire le problème "bar-chart sur des counts de 1" déjà corrigé ailleurs (vendors/CWE)."""
    scores = [item["cvss_score"] for item in critical_items if item.get("cvss_score") is not None]
    if len(scores) < _HISTOGRAM_MIN_ITEMS:
        return None

    lo, hi = min(scores), max(scores)
    span = (hi - lo) or 1
    bin_width = span / bins
    counts = [0] * bins
    for s in scores:
        idx = min(int((s - lo) / bin_width), bins - 1)
        counts[idx] += 1
    max_count = max(counts) or 1

    top_margin, bottom_margin = 14, 24
    plot_height = height - top_margin - bottom_margin
    baseline_y = height - bottom_margin
    bar_width = width / bins
    gap = 6

    bars = []
    for i, c in enumerate(counts):
        bar_h = (c / max_count) * plot_height
        x = i * bar_width + gap / 2
        y = baseline_y - bar_h
        bar_w = bar_width - gap
        bars.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{max(bar_h, 1):.1f}" rx="3" fill="{_HISTOGRAM_COLOR}"/>'
        )
        bars.append(
            f'<text x="{x + bar_w / 2:.1f}" y="{y - 4:.1f}" text-anchor="middle" fill="{_TEXT_BODY_COLOR}" '
            f'font-family="JetBrains Mono, monospace" font-size="9">{c}</text>'
        )
        label = f"{lo + i * bin_width:.1f}-{lo + (i + 1) * bin_width:.1f}"
        bars.append(
            f'<text x="{x + bar_w / 2:.1f}" y="{height - 6}" text-anchor="middle" fill="{_TEXT_MUTED_COLOR}" '
            f'font-family="JetBrains Mono, monospace" font-size="8">{label}</text>'
        )

    return (
        f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" class="cvss-histogram">'
        + "".join(bars)
        + "</svg>"
    )


def _build_history_line_chart_svg(
    cve_series: list[float], kev_series: list[float], c2_series: list[float], width: int = 320, height: int = 110
) -> str | None:
    series = {"cve": cve_series, "kev": kev_series, "c2": c2_series}
    lengths = {len(v) for v in series.values()}
    if len(lengths) != 1 or lengths == {0}:
        return None
    n = next(iter(lengths))
    if n < _LINE_MIN_POINTS:
        return None

    all_values = [v for values in series.values() for v in values]
    lo, hi = min(all_values), max(all_values)
    span = (hi - lo) or 1
    margin = 6
    plot_h = height - margin * 2
    step = width / (n - 1)

    def _polyline(values: list[float], color: str) -> str:
        points = " ".join(
            f"{i * step:.1f},{margin + plot_h - ((v - lo) / span * plot_h):.1f}" for i, v in enumerate(values)
        )
        return f'<polyline points="{points}" fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>'

    lines = "".join(_polyline(values, _LINE_SERIES_COLORS[key]) for key, values in series.items())
    return f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" class="history-line-chart">{lines}</svg>'


def _build_executive_summary(
    kpis: ReportKpis,
    is_cold_start: bool,
    sources_status: dict[str, str],
    c2_cross_confirmed: dict | None = None,
) -> str:
    """Synthèse en 2-4 phrases, langage simple — public cible : recruteur non-expert cyber
    (CDC §1). Jamais de comparaison "vs semaine dernière" sur un cold start (CDC §6)."""

    def trend_phrase(pct: float | None) -> str:
        if is_cold_start or pct is None:
            return ""
        if pct > 0:
            return f", up {pct:.0f}% from last week"
        if pct < 0:
            return f", down {abs(pct):.0f}% from last week"
        return ", unchanged from last week"

    sentences = [
        f"This week, the pipeline tracked {kpis.cve_critical_count} new critical CVEs"
        f"{trend_phrase(kpis.cve_critical_trend_pct)}."
    ]

    kev_sentence = f"{kpis.kev_new_count} were added to CISA's Known Exploited Vulnerabilities catalog"
    if kpis.kev_urgent_count > 0:
        kev_sentence += f", {kpis.kev_urgent_count} of them due for patching within 7 days"
    if kpis.kev_ransomware_count > 0:
        kev_sentence += ", including at least one tied to known ransomware activity"
    sentences.append(kev_sentence + ".")

    c2_noun = "server" if kpis.c2_active_count == 1 else "servers"
    c2_verb = "remains" if kpis.c2_active_count == 1 else "remain"
    sentences.append(
        f"{kpis.c2_active_count} command-and-control {c2_noun} {c2_verb} active and "
        f"{kpis.malicious_url_count} malicious URLs were seen online in the monitored feeds."
    )

    # Omis si aucune des 3 sources d'enrichissement C2 (Shodan/Spamhaus/GreyNoise) n'a tourné
    # ce run — cf. _c2_cross_confirmed, qui retourne None dans ce cas précisément pour que ce
    # bloc n'affiche jamais un faux "0 confirmés" quand rien n'a réellement été vérifié.
    if c2_cross_confirmed is not None:
        confirmed = c2_cross_confirmed["confirmed"]
        noun = "server" if confirmed == 1 else "servers"
        verb = "was" if confirmed == 1 else "were"
        sentences.append(
            f"{confirmed} of this week's active C2 {noun} {verb} independently confirmed by more than one threat feed."
        )

    degraded = [name for name, status in sources_status.items() if status.startswith(_DEGRADED_STATUS_PREFIXES)]
    if degraded:
        sentences.append(
            f"Note: {', '.join(sorted(degraded))} did not respond normally this run — "
            "the pipeline continued with the remaining sources rather than failing outright."
        )

    return " ".join(sentences)


def _geo_top_countries(feodo_df: pl.DataFrame, n: int) -> list[dict]:
    if feodo_df.height == 0 or "country" not in feodo_df.columns:
        return []
    counted = (
        feodo_df.filter(pl.col("country").is_not_null())
        .group_by("country")
        .agg(pl.len().alias("count"))
        .sort("count", descending=True)
    )
    total = counted["count"].sum()
    if not total:
        return []
    rows = counted.head(n).to_dicts()
    return [
        {
            "country_name": country_name(row["country"]),
            "country_code": row["country"],
            "count": row["count"],
            "pct_of_total": round(row["count"] / total * 100, 1),
        }
        for row in rows
    ]


def _cwe_top_items(cwe_distribution: list[dict], n: int) -> list[dict]:
    total = sum(row["count"] for row in cwe_distribution)
    if not total:
        return []
    return [
        {
            "cwe_id": row["cwe_id"],
            "cwe_name": cwe_name(row["cwe_id"]),
            "count": row["count"],
            "pct_of_total": round(row["count"] / total * 100, 1),
        }
        for row in cwe_distribution[:n]
    ]


def _chip_breakdown(items: list[dict], key: str, out_key: str, n: int) -> list[dict]:
    """Group-by + count + pct_of_total sur une liste de dicts (pas un DataFrame polars — c2_items/
    malicious_url_items sont déjà des listes Python à ce stade), même forme que _geo_top_countries/
    _cwe_top_items. 1-2 entrées à count=1 chacune ne portent aucun signal de distribution réel
    (même discipline que _HISTOGRAM_MIN_ITEMS) -> [] plutôt qu'un chip-list vide de sens."""
    counted: dict[str, int] = {}
    for item in items:
        value = item.get(key)
        if value:
            counted[value] = counted.get(value, 0) + 1
    if not counted:
        return []
    if len(counted) <= 2 and all(count == 1 for count in counted.values()):
        return []
    total = sum(counted.values())
    rows = sorted(counted.items(), key=lambda kv: kv[1], reverse=True)[:n]
    return [{out_key: name, "count": count, "pct_of_total": round(count / total * 100, 1)} for name, count in rows]


def _open_ports_breakdown(c2_items: list[dict], n: int) -> list[dict]:
    """Aplatit c2_items[].open_ports (Shodan InternetDB) avant de réutiliser _chip_breakdown —
    même pattern que malware_family_breakdown/top_asn ci-dessous, un pseudo-item par port ouvert
    plutôt que par IP. Sous _PORT_BREAKDOWN_MIN_IPS IP avec des ports reportés -> [] (pas de
    chart plutôt qu'un chip-list sur 1-2 IP, même discipline que _HISTOGRAM_MIN_ITEMS)."""
    ips_with_ports = sum(1 for item in c2_items if item.get("open_ports"))
    if ips_with_ports < _PORT_BREAKDOWN_MIN_IPS:
        return []
    flattened = [{"port": port} for item in c2_items for port in (item.get("open_ports") or [])]
    return _chip_breakdown(flattened, "port", "port", n)


def _c2_cross_confirmed(c2_items: list[dict], sources_status: dict[str, str]) -> dict | None:
    """ "Cross-confirmé" = au moins 2 signaux indépendants parmi les 3 nouvelles sources IP
    (Spamhaus DROP/EDROP match, GreyNoise classification == "malicious", Shodan InternetDB ayant
    des données pour cette IP) — FeodoTracker/ThreatFox eux-mêmes ne comptent pas comme un 4e
    signal, ils sont déjà la source de base de toute la section C2.
    GreyNoise "unknown" ne compte PAS comme confirmation (ça veut dire "non classé", zéro
    information dans un sens ou l'autre) — seul "malicious" est un signal positif. La spec
    initiale envisageait "GreyNoise non-scanner", mais GreyNoise n'a pas de valeur "scanner" en
    classification (vérifié docs.greynoise.io) : "benign" y désigne une IP RIOT (infra de
    confiance connue), pas un scanner — donc "malicious" est le signal le plus proche et le plus
    défendable, cf. extract/greynoise.py.
    Retourne None si aucune des 3 sources n'a répondu "ok" ce run (rien à confirmer réellement -
    évite d'afficher un "0/N" qui laisserait croire à une vérification qui n'a pas eu lieu)."""
    if not any(sources_status.get(name) == "ok" for name in ("shodan_internetdb", "spamhaus_drop", "greynoise")):
        return None
    total = len(c2_items)
    if not total:
        return None
    confirmed = 0
    for item in c2_items:
        signals = sum(
            (
                bool(item.get("confirmed_by_spamhaus")),
                item.get("greynoise_classification") == "malicious",
                bool(item.get("shodan_has_data")),
            )
        )
        if signals >= 2:
            confirmed += 1
    return {"confirmed": confirmed, "total": total}


def _kev_items(kev_df: pl.DataFrame) -> list[dict]:
    if kev_df.height == 0:
        return []
    items = []
    for row in kev_df.to_dicts():
        date_added = row.get("date_added")
        items.append(
            {
                "cve_id": row["cve_id"],
                "vendor_project": row.get("vendor_project"),
                "product": row.get("product"),
                "date_added": date_added.isoformat() if hasattr(date_added, "isoformat") else date_added,
                "ransomware_known_use": row.get("known_ransomware_campaign_use") == "Known",
            }
        )
    return items


def build_c2_items(top_ips: list[dict]) -> list[dict]:
    # open_ports/known_cves/confirmed_by_spamhaus/greynoise_classification/shodan_has_data sont
    # déjà posés sur top_ips par orchestrate.py::_build_top_ips (merge post rank_top_n_ips, cf.
    # CDC "Data source integration rule") — cette fonction ne fait que les faire passer dans le
    # dict template-ready, même rôle que pour country/asn/malware ci-dessous.
    return [
        {
            "ip_address": item["ip"],
            "country": item.get("country"),
            "asn": item.get("asn"),
            "malware_family": item.get("malware"),
            "first_seen": item.get("first_seen"),
            "last_online": item.get("last_seen"),
            "lat": item.get("lat"),
            "lon": item.get("lon"),
            "open_ports": item.get("open_ports") or [],
            "known_cves": item.get("known_cves") or [],
            "confirmed_by_spamhaus": bool(item.get("confirmed_by_spamhaus")),
            "greynoise_classification": item.get("greynoise_classification"),
            "shodan_has_data": bool(item.get("shodan_has_data")),
        }
        for item in top_ips
    ]


def build_malicious_url_items(ranked_urlhaus_df: pl.DataFrame) -> list[dict]:
    if ranked_urlhaus_df.height == 0:
        return []
    items = []
    for row in ranked_urlhaus_df.to_dicts():
        url = row["url"]
        if len(url) > _URL_TRUNCATE_LEN:
            # "..." ASCII plutôt que le glyphe unicode "…" : absent des webfonts embarqués
            # (Syne/PJS/JetBrains Mono, subsets Latin), provoquerait un fallback système
            # (police interdite, cf. lot 5 "aucune police système de fallback").
            url = url[: _URL_TRUNCATE_LEN - 3] + "..."
        date_added = row.get("date_added")
        items.append(
            {
                "url": url,
                "threat_type": row.get("threat"),
                "tags": row.get("tags") or [],
                "date_added": date_added.isoformat() if hasattr(date_added, "isoformat") else date_added,
                # ["urlhaus"] par défaut : lignes construites avant le merge PhishTank (ou runs où
                # PhishTank est skip/failed) n'ont jamais de colonne "sources" du tout.
                "sources": row.get("sources") or ["urlhaus"],
            }
        )
    return items


def build_pdf_context(
    *,
    run_id: str,
    period_start: datetime,
    period_end: datetime,
    generated_at: datetime,
    kpis: ReportKpis,
    critical_items: list[dict],
    kev_df: pl.DataFrame,
    mttk_median_days: float | None,
    mttk_sample_size: int,
    feodo_df: pl.DataFrame,
    c2_items: list[dict],
    malicious_url_items: list[dict],
    pipeline_duration_seconds: float,
    sources_status: dict[str, str],
    is_cold_start: bool,
    history_entries: list[dict],
) -> dict:
    period_start_str = _fmt_date(period_start)
    period_end_str = _fmt_date(period_end)
    generated_at_str = _fmt_date(generated_at)

    def _series(key: str, current: int) -> list[float]:
        return [h[key] for h in history_entries if key in h] + [current]

    threatfox_enabled = sources_status.get("threatfox") == "ok"
    c2_cross_confirmed = _c2_cross_confirmed(c2_items, sources_status)

    return {
        "report": {
            "run_id": run_id,
            "period_start": period_start_str,
            "period_end": period_end_str,
            "generated_at": generated_at_str,
            "kpi_summary": {
                "cve_critical_count": kpis.cve_critical_count,
                "kev_new_count": kpis.kev_new_count,
                "c2_active_count": kpis.c2_active_count,
                "malicious_url_count": kpis.malicious_url_count,
            },
        },
        "executive_summary": _build_executive_summary(kpis, is_cold_start, sources_status, c2_cross_confirmed),
        "sources_status": [{"name": name, "status": status} for name, status in sorted(sources_status.items())],
        "cve": {
            "critical_count": kpis.cve_critical_count,
            "critical_trend_pct": kpis.cve_critical_trend_pct,
            "high_volume_count": kpis.cve_high_count,
            "critical_items": critical_items,
            "sparkline": _build_sparkline_svg(_series("cve_critical_count", kpis.cve_critical_count)),
            "severity_donut": _build_severity_donut_svg(kpis.cve_critical_count, kpis.cve_high_count),
            "cvss_histogram": _build_cvss_histogram_svg(critical_items),
        },
        "kev": {
            "new_count": kpis.kev_new_count,
            "trend_pct": kpis.kev_new_trend_pct,
            "urgent_count": kpis.kev_urgent_count,
            "items": _kev_items(kev_df),
            "urgency_flag": kpis.kev_ransomware_count > 0,
            "sparkline": _build_sparkline_svg(_series("kev_new_count", kpis.kev_new_count)),
        },
        "mttk": {
            "average_days": kpis.mean_time_to_kev_days,
            "median_days": mttk_median_days,
            "sample_size": mttk_sample_size,
        },
        "c2": {
            "active_count": kpis.c2_active_count,
            "trend_pct": kpis.c2_active_trend_pct,
            "items": c2_items,
            "sparkline": _build_sparkline_svg(_series("c2_active_count", kpis.c2_active_count)),
            "map_svg": _build_world_map_svg(c2_items),
            "malware_family_breakdown": _chip_breakdown(c2_items, "malware_family", "malware_family", _TOP_N_COUNTRIES),
            "top_asn": _chip_breakdown(c2_items, "asn", "asn", _TOP_N_COUNTRIES),
            "open_ports_breakdown": _open_ports_breakdown(c2_items, _TOP_N_COUNTRIES),
            "cross_confirmed": c2_cross_confirmed,
        },
        "malicious_urls": {
            "online_count": kpis.malicious_url_count,
            "trend_pct": kpis.malicious_url_trend_pct,
            "items": malicious_url_items,
            "sparkline": _build_sparkline_svg(_series("malicious_url_count", kpis.malicious_url_count)),
            "threat_type_breakdown": _chip_breakdown(
                malicious_url_items, "threat_type", "threat_type", _TOP_N_COUNTRIES
            ),
        },
        "threatfox": {
            "enabled": threatfox_enabled,
            "families_count": kpis.threatfox_malware_families_count,
            "families_trend_pct": kpis.threatfox_malware_families_trend_pct,
            "sparkline": _build_sparkline_svg(
                _series("threatfox_malware_families_count", kpis.threatfox_malware_families_count)
            ),
        },
        "geo": {
            "top_countries": _geo_top_countries(feodo_df, _TOP_N_COUNTRIES),
        },
        "history_chart": {
            "svg": _build_history_line_chart_svg(
                _series("cve_critical_count", kpis.cve_critical_count),
                _series("kev_new_count", kpis.kev_new_count),
                _series("c2_active_count", kpis.c2_active_count),
            ),
            "legend": [
                {"label": "Critical CVEs", "color": _LINE_SERIES_COLORS["cve"]},
                {"label": "New KEV entries", "color": _LINE_SERIES_COLORS["kev"]},
                {"label": "Active C2 IPs", "color": _LINE_SERIES_COLORS["c2"]},
            ],
        },
        "vendors": {
            "top_items": [{"vendor_name": row["vendor"], "cve_count": row["count"]} for row in kpis.top_vendors],
        },
        "cwe": {
            "top_items": _cwe_top_items(kpis.cwe_distribution, _TOP_N_COUNTRIES),
        },
        "lineage": {
            "run_id": run_id,
            "period_start": period_start_str,
            "period_end": period_end_str,
            "generated_at": generated_at_str,
            "sources": _SOURCES,
            "pipeline_duration_seconds": round(pipeline_duration_seconds, 2),
        },
    }
