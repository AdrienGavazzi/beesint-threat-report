from __future__ import annotations

import math
from datetime import datetime

import polars as pl

from beesint_threat_report.load.countries import country_name
from beesint_threat_report.load.cwe_names import cwe_name
from beesint_threat_report.load.world_borders_path import WORLD_BORDERS_PATH_D
from beesint_threat_report.load.world_map_path import WORLD_LANDMASS_PATH_D
from beesint_threat_report.transform.kpis import ReportKpis

_TOP_N_COUNTRIES = 10
_URL_TRUNCATE_LEN = 80

# "category" groupe les sources pour la section Pipeline Lineage & Source Attribution (refonte
# liste sobre, pas de card look — cf. _lineage.html.j2) : 4 groupes fixes couvrant les 4 grandes
# familles de données du rapport (CVE/KEV, C2 infra + son enrichissement IP, URLs malveillantes,
# géolocalisation). Shodan/Spamhaus/GreyNoise classées "C2" : ce sont des sources d'enrichissement
# des mêmes IP C2 (cf. CDC "Data source integration rule"), pas une catégorie à part.
_SOURCES = [
    {
        "name": "NVD (National Vulnerability Database)",
        "url": "https://nvd.nist.gov/",
        "note": "Domaine public — NIST.",
        "category": "CVE / KEV",
    },
    {
        "name": "CISA Known Exploited Vulnerabilities (KEV)",
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "note": "Domaine public — CISA.",
        "category": "CVE / KEV",
    },
    {
        "name": "abuse.ch FeodoTracker",
        "url": "https://feodotracker.abuse.ch/",
        "note": "Data kindly provided by abuse.ch",
        "category": "C2 Infrastructure",
    },
    {
        "name": "abuse.ch URLhaus",
        "url": "https://urlhaus.abuse.ch/",
        "note": "Data kindly provided by abuse.ch",
        "category": "Malicious URLs",
    },
    {
        "name": "abuse.ch ThreatFox",
        "url": "https://threatfox.abuse.ch/",
        "note": "Data kindly provided by abuse.ch",
        "category": "C2 Infrastructure",
    },
    {
        "name": "ip-api.com",
        "url": "https://ip-api.com/",
        "note": "Géolocalisation IP, usage non-commercial.",
        "category": "Geolocation",
    },
    {
        "name": "Shodan InternetDB",
        "url": "https://internetdb.shodan.io/",
        "note": "Domaine public — gratuit, sans clé API.",
        "category": "C2 Infrastructure",
    },
    {
        "name": "Spamhaus DROP/EDROP",
        "url": "https://www.spamhaus.org/drop/",
        "note": "Listes CIDR publiques — usage non-commercial.",
        "category": "C2 Infrastructure",
    },
    {
        "name": "GreyNoise Community API",
        "url": "https://viz.greynoise.io/",
        "note": "Tier gratuit, clé API requise — classification IP.",
        "category": "C2 Infrastructure",
    },
    {
        "name": "OpenPhish",
        "url": "https://openphish.com/",
        "note": "Flux public communautaire — gratuit, sans clé API.",
        "category": "Malicious URLs",
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
# Distinct du reste de la palette map (voir _build_world_map_svg) — plus clair que
# --color-bg-elevated (#1a1f2e, fond de .map-frame) pour que la silhouette se détache clairement.
_MAP_LAND_COLOR = "#293552"
_DONUT_CRITICAL_COLOR = "#EF4444"  # --color-error
_DONUT_HIGH_COLOR = "#F59E0B"  # --color-warning
_HISTOGRAM_COLOR = "#0EA5E9"  # --color-primary
_HISTOGRAM_MIN_ITEMS = 6  # sous ce seuil, un histogramme par bin serait aussi peu lisible que
# les bar-charts count=1 déjà bannis ailleurs (vendors/CWE) — cf. philosophie du fichier.
# Frontière C2 sur la carte (nouveau path statique, cf. world_borders_path.py) — ton neutre
# discret, distinct à la fois de _MAP_LAND_COLOR (masse continentale) et des couleurs de rang
# ci-dessous (dots), pour rester un repère de fond plutôt qu'une donnée.
_MAP_BORDER_COLOR = "#4A6080"  # --color-entity-other, réutilisé comme gris-bleu neutre

# Palette catégorielle "rang -> couleur", tokens --color-entity-* du design system frontend (cf.
# CLAUDE.md racine, ENTITY_COLORS dans beesint-frontend/src/types/index.ts) — copiés ici au même
# titre que les autres tokens dupliqués en tête de report.css (repos indépendants, à
# resynchroniser manuellement si la DA change côté frontend). Assignation déterministe par rang
# (index 0 = valeur la plus fréquente d'un classement déjà trié par _chip_breakdown) : UNE SEULE
# constante consommée à la fois par les mini-bar-charts (barres), la carte C2 (points) et les
# cellules de tableau correspondantes (malware family/ASN), pour qu'un même nom ait toujours la
# même couleur partout où il apparaît dans la section C2.
_RANK_COLOR_TOKENS = [
    "#0EA5E9",  # --color-entity-domain
    "#f59e0b",  # --color-entity-ip
    "#22c55e",  # --color-entity-email
    "#06b6d4",  # --color-entity-username
    "#a855f7",  # --color-entity-organization
    "#ec4899",  # --color-entity-certificate
    "#ef4444",  # --color-entity-hash-leak
    "#4A6080",  # --color-entity-other
]


def _rank_color(rank: int) -> str:
    return _RANK_COLOR_TOKENS[rank % len(_RANK_COLOR_TOKENS)]


def _attach_rank_colors(rows: list[dict]) -> list[dict]:
    """Attache `color` (palette ci-dessus, index = position dans `rows`) à une liste déjà triée
    par _chip_breakdown/_open_ports_breakdown (rang 0 = valeur la plus fréquente). Retourne une
    NOUVELLE liste de dicts (jamais de mutation en place — ces rows peuvent être réutilisées
    telles quelles ailleurs)."""
    return [{**row, "color": _rank_color(i)} for i, row in enumerate(rows)]


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


def _sanitize_status(status: str) -> str:
    """Strips the detailed skip/failure reason (e.g. "skipped:no_api_key" -> "skipped") for
    public-facing surfaces (PDF, public web badge). The full reason stays available in whatever
    the ETL logs stdout (run_id, per-source status) and in the raw `sources_status` dict this
    function's caller still has before sanitizing — nothing upstream of this display boundary
    loses the detail, only the PDF/public rendering does."""
    return status.split(":", 1)[0]


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


def _build_world_map_svg(
    items: list[dict], dot_color_by_malware: dict[str, str] | None = None, width: int = 480, height: int = 220
) -> str | None:
    """Scatter équirectangulaire pur SVG (pas de tuiles/basemap : aucun appel réseau depuis le
    rendu PDF, cf. philosophie "continue en dégradé" — un run ETL ne doit jamais dépendre de la
    disponibilité d'un service tiers juste pour dessiner une carte).

    Pas de largeur/hauteur fixes sur la racine <svg> (seulement viewBox) : `.map-frame svg` pose
    `width:100%; height:auto` côté CSS pour que la carte remplisse la card plutôt que de rendre en
    dessous de l'espace dispo (vérifié empiriquement — des attributs width/height fixes sur <svg>
    ignorent la largeur réelle du conteneur). Graticule lon/lat retirée : elle précédait la
    silhouette réelle (placeholder) et, une fois superposée à `_MAP_LAND_COLOR`, ne faisait que se
    confondre visuellement avec le contour des continents sans rien ajouter.

    dot_color_by_malware : mapping malware_family -> couleur (palette _RANK_COLOR_TOKENS, cf.
    _attach_rank_colors) — même dict que celui utilisé pour colorer la colonne "Malware family"
    du tableau C2, pour qu'un point sur la carte matche toujours la couleur du nom en table.
    Fallback _MAP_DOT_COLOR si absent (item sans malware_family connue, ou mapping non fourni)."""
    dot_color_by_malware = dot_color_by_malware or {}
    points = [
        (item["lon"], item["lat"], dot_color_by_malware.get(item.get("malware_family"), _MAP_DOT_COLOR))
        for item in items
        if item.get("lat") is not None and item.get("lon") is not None
    ]
    if not points:
        return None

    def _project(lon: float, lat: float) -> tuple[float, float]:
        return (lon + 180) / 360 * width, (90 - lat) / 180 * height

    dots = []
    for lon, lat, color in points:
        x, y = _project(lon, lat)
        dots.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4" fill="{color}" fill-opacity="0.9" '
            f'stroke="{color}" stroke-opacity="0.25" stroke-width="5"/>'
        )

    # Couleur dédiée, distincte de _GRID_COLOR (qui ne sert plus que de teinte de fallback
    # ailleurs) — _GRID_COLOR partagé entre graticule/silhouette rendait les deux indiscernables
    # au rendu (bug confirmé visuellement). _MAP_LAND_COLOR est délibérément plus clair que
    # --color-bg-elevated (fond de .map-frame) pour se détacher nettement comme "terre" sur "mer".
    landmass = f'<path d="{WORLD_LANDMASS_PATH_D}" fill="{_MAP_LAND_COLOR}" fill-opacity="0.9"/>'
    # Frontières politiques (world_borders_path.py) — dataset Natural Earth dédié "boundary lines
    # land" (pas les polygones de pays), donc aucun doublon avec le contour de landmass déjà
    # dessiné ci-dessus. Stroke fin, faible opacité : repère de fond, ne doit pas rivaliser
    # visuellement avec les points de données (dots).
    borders = (
        f'<path d="{WORLD_BORDERS_PATH_D}" fill="none" stroke="{_MAP_BORDER_COLOR}" '
        f'stroke-opacity="0.5" stroke-width="0.6"/>'
    )

    return f'<svg viewBox="0 0 {width} {height}" class="world-map">' + landmass + borders + "".join(dots) + "</svg>"


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
    cve_series: list[float], kev_series: list[float], c2_series: list[float], width: int = 480, height: int = 130
) -> str | None:
    """Ce chart vit toujours dans une card en pleine largeur de section (chart-card avec
    flex-basis:100%, cf. templates) — pas de width/height fixes sur la racine <svg> (seulement
    viewBox), même raison que _build_world_map_svg : sur WeasyPrint 62.3, des attributs
    width/height fixes sur <svg> ignorent la largeur réelle du conteneur même quand une règle CSS
    tente de forcer width:100% dessus (vérifié empiriquement — cf. CLAUDE.md "WeasyPrint 62.3").
    Axe Y minimal (2 ticks : min/max de la série la plus large) plutôt qu'une grille complète :
    3 séries à échelles très différentes (CVE ~dizaines, C2 souvent <5) rendraient un axe partagé
    à graduations régulières illisible pour les séries basses — seuls min/max donnent un repère
    utile sans fabriquer une fausse précision."""
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
    axis_w = 22  # largeur réservée aux labels de l'axe Y (JetBrains Mono 7px)
    top_margin, bottom_margin = 6, 6
    plot_w = width - axis_w
    plot_h = height - top_margin - bottom_margin
    step = plot_w / (n - 1)

    def _y(v: float) -> float:
        return top_margin + plot_h - ((v - lo) / span * plot_h)

    def _polyline(values: list[float], color: str) -> str:
        points = " ".join(f"{axis_w + i * step:.1f},{_y(v):.1f}" for i, v in enumerate(values))
        return f'<polyline points="{points}" fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>'

    axis = []
    for value in (lo, hi):
        y = _y(value)
        axis.append(
            f'<line x1="{axis_w}" y1="{y:.1f}" x2="{width}" y2="{y:.1f}" stroke="{_GRID_COLOR}" stroke-width="0.5"/>'
        )
        axis.append(
            f'<text x="{axis_w - 4:.1f}" y="{y + 2.5:.1f}" text-anchor="end" fill="{_TEXT_MUTED_COLOR}" '
            f'font-family="JetBrains Mono, monospace" font-size="7">{value:.0f}</text>'
        )

    lines = "".join(_polyline(values, _LINE_SERIES_COLORS[key]) for key, values in series.items())
    return f'<svg viewBox="0 0 {width} {height}" class="history-line-chart">' + "".join(axis) + lines + "</svg>"


def _build_area_chart_svg(
    values: list[float], width: int = 480, height: int = 130, color: str = _SPARKLINE_COLOR
) -> str | None:
    """Graphique de tendance dédié à une seule série (utilisé pour malicious URLs, dont l'échelle
    en milliers rendrait un axe partagé avec CVE/KEV/C2 illisible, cf. commentaire sur
    _LINE_SERIES_COLORS ci-dessus). Ligne + remplissage dégradé, même garde-fou que le sparkline
    (retourne None sous _LINE_MIN_POINTS points).
    Vit aussi dans une card en pleine largeur (flex-basis:100%) — pas de width/height fixes sur la
    racine <svg>, même raison que _build_history_line_chart_svg/_build_world_map_svg (cf. CLAUDE.md
    "WeasyPrint 62.3")."""
    if len(values) < _LINE_MIN_POINTS:
        return None
    lo, hi = min(values), max(values)
    span = (hi - lo) or 1
    margin = 10
    plot_h = height - margin * 2
    step = width / (len(values) - 1)

    points = [(i * step, margin + plot_h - ((v - lo) / span * plot_h)) for i, v in enumerate(values)]
    line_points = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
    area_points = f"0,{height} " + line_points + f" {width},{height}"

    return (
        f'<svg viewBox="0 0 {width} {height}" class="area-chart">'
        f'<polygon points="{area_points}" fill="{color}" fill-opacity="0.14"/>'
        f'<polyline points="{line_points}" fill="none" stroke="{color}" stroke-width="2" '
        f'stroke-linecap="round" stroke-linejoin="round"/>'
        f"</svg>"
    )


def _build_mini_bar_chart_svg(
    rows: list[dict], label_key: str, count_key: str = "count", width: int = 340, height: int = 100
) -> str | None:
    """Bar-chart horizontal générique pour une liste déjà agrégée par _chip_breakdown (name +
    count + pct_of_total, triée descendante). Ne rend rien si la distribution est plate (même
    count sur la première et la dernière entrée) — un bar-chart n'ajoute aucun signal qu'un chiffre
    ne dise déjà dans ce cas précis, même discipline que _HISTOGRAM_MIN_ITEMS/le chip-list déjà en
    place pour countries/vendors."""
    if len(rows) < 2 or rows[0][count_key] == rows[-1][count_key]:
        return None

    max_count = max(row[count_key] for row in rows) or 1
    row_h = height / len(rows)
    bar_h = row_h * 0.55
    label_w = 120  # tient "malware_download" (17 car.) sans tronquer sur fond de card standard
    plot_w = width - label_w - 30

    bars = []
    for i, row in enumerate(rows):
        y = i * row_h + (row_h - bar_h) / 2
        bar_w = max((row[count_key] / max_count) * plot_w, 2)
        label = str(row[label_key])[:18]
        # row["color"] : présent quand `rows` vient de _attach_rank_colors (C2 breakdowns) — même
        # couleur que le point carte/la cellule de tableau correspondante. Fallback
        # _HISTOGRAM_COLOR (bleu unique) pour les appelants qui ne posent pas ce champ
        # (threat_type_breakdown notamment, hors périmètre de la palette par rang).
        bar_color = row.get("color") or _HISTOGRAM_COLOR
        bars.append(
            f'<text x="0" y="{y + bar_h / 2 + 3:.1f}" fill="{_TEXT_MUTED_COLOR}" '
            f'font-family="JetBrains Mono, monospace" font-size="8.5">{label}</text>'
        )
        bars.append(
            f'<rect x="{label_w}" y="{y:.1f}" width="{bar_w:.1f}" height="{bar_h:.1f}" rx="2" fill="{bar_color}"/>'
        )
        bars.append(
            f'<text x="{label_w + bar_w + 6:.1f}" y="{y + bar_h / 2 + 3:.1f}" fill="{_TEXT_BODY_COLOR}" '
            f'font-family="JetBrains Mono, monospace" font-size="8.5">{row[count_key]}</text>'
        )

    return (
        f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" class="mini-bar-chart">'
        + "".join(bars)
        + "</svg>"
    )


_MTTK_GAUGE_MAX_DAYS = 45  # au-delà, l'aiguille se cale au maximum plutôt que de sortir du cadran
_MTTK_ZONE_GREEN_MAX = 7  # <7j : encore un délai de réaction raisonnable
_MTTK_ZONE_AMBER_MAX = 30  # 7-30j : fenêtre resserrée : au-delà, retard jugé critique (zone rouge)


def _build_mttk_gauge_svg(median_days: float, size: int = 200) -> str:
    """Jauge semi-circulaire à zones de couleur (vert/ambre/rouge) avec aiguille sur la médiane.
    Toujours un rendu (pas de None) : appelé uniquement quand sample_size > 0 côté template, donc
    median_days est déjà garanti réel à ce stade."""
    cx, cy, r, stroke = size / 2, size * 0.56, size * 0.4, size * 0.12

    def _point(angle_deg: float) -> tuple[float, float]:
        rad = math.radians(angle_deg)
        return cx + r * math.cos(rad), cy - r * math.sin(rad)

    def _value_to_angle(v: float) -> float:
        v_clamped = max(0.0, min(v, _MTTK_GAUGE_MAX_DAYS))
        return 180 - (v_clamped / _MTTK_GAUGE_MAX_DAYS) * 180

    zones = [
        (0, _MTTK_ZONE_GREEN_MAX, "#22C55E"),  # --color-success
        (_MTTK_ZONE_GREEN_MAX, _MTTK_ZONE_AMBER_MAX, "#F59E0B"),  # --color-warning
        (_MTTK_ZONE_AMBER_MAX, _MTTK_GAUGE_MAX_DAYS, "#EF4444"),  # --color-error
    ]
    arcs = []
    for start, end, color in zones:
        x1, y1 = _point(_value_to_angle(start))
        x2, y2 = _point(_value_to_angle(end))
        arcs.append(
            f'<path d="M {x1:.1f} {y1:.1f} A {r:.1f} {r:.1f} 0 0 1 {x2:.1f} {y2:.1f}" '
            f'fill="none" stroke="{color}" stroke-width="{stroke:.1f}" stroke-linecap="butt"/>'
        )

    needle_angle = _value_to_angle(median_days)
    nx, ny = _point(needle_angle)
    needle = (
        f'<line x1="{cx}" y1="{cy}" x2="{nx:.1f}" y2="{ny:.1f}" stroke="{_TEXT_BODY_COLOR}" stroke-width="2.5" '
        f'stroke-linecap="round"/><circle cx="{cx}" cy="{cy}" r="4" fill="{_TEXT_BODY_COLOR}"/>'
    )
    label = (
        f'<text x="{cx}" y="{cy + size * 0.22:.1f}" text-anchor="middle" fill="{_TEXT_BODY_COLOR}" '
        f'font-family="JetBrains Mono, monospace" font-size="20" font-weight="700">{median_days:.1f}d</text>'
        f'<text x="{cx}" y="{cy + size * 0.22 + 14:.1f}" text-anchor="middle" fill="{_TEXT_MUTED_COLOR}" '
        f'font-family="JetBrains Mono, monospace" font-size="8" letter-spacing="1">MEDIAN</text>'
    )

    return (
        f'<svg width="{size}" height="{size * 0.66:.0f}" viewBox="0 0 {size} {size * 0.66:.0f}" class="mttk-gauge">'
        + "".join(arcs)
        + needle
        + label
        + "</svg>"
    )


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


_SOURCE_CATEGORY_ORDER = ["CVE / KEV", "C2 Infrastructure", "Malicious URLs", "Geolocation"]


def _sources_by_category(sources: list[dict]) -> list[dict]:
    """Groupe _SOURCES par `category` (cf. _SOURCE_CATEGORY_ORDER) pour la refonte "liste sobre"
    de la section Pipeline Lineage (plus de card look, cf. _lineage.html.j2) — l'ordre des
    catégories est fixe (pas alphabétique), pour suivre l'ordre des sections du rapport
    (CVE/KEV -> C2 -> URLs malveillantes -> géoloc)."""
    grouped: dict[str, list[dict]] = {}
    for source in sources:
        grouped.setdefault(source["category"], []).append(source)
    return [
        {"category": category, "sources": grouped[category]}
        for category in _SOURCE_CATEGORY_ORDER
        if category in grouped
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

    # Breakdowns C2 colorés par rang (cf. _attach_rank_colors) — calculés une fois ici, réutilisés
    # à la fois pour les mini-bar-charts, la légende de la carte et les mappings malware/asn ->
    # couleur consommés par la carte (dots) et le tableau (cellules), pour qu'un même nom porte
    # toujours la même couleur partout dans la section C2 (cf. CDC Phase B point 8).
    _mf_breakdown = _attach_rank_colors(_chip_breakdown(c2_items, "malware_family", "malware_family", _TOP_N_COUNTRIES))
    _asn_breakdown = _attach_rank_colors(_chip_breakdown(c2_items, "asn", "asn", _TOP_N_COUNTRIES))
    _ports_breakdown = _attach_rank_colors(_open_ports_breakdown(c2_items, _TOP_N_COUNTRIES))
    _malware_color_by_name = {row["malware_family"]: row["color"] for row in _mf_breakdown}
    _asn_color_by_name = {row["asn"]: row["color"] for row in _asn_breakdown}

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
        "sources_status": [
            {"name": name, "status": _sanitize_status(status)} for name, status in sorted(sources_status.items())
        ],
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
            "gauge_svg": _build_mttk_gauge_svg(mttk_median_days)
            if mttk_sample_size > 0 and mttk_median_days is not None
            else None,
        },
        "c2": {
            "active_count": kpis.c2_active_count,
            "trend_pct": kpis.c2_active_trend_pct,
            "items": c2_items,
            "sparkline": _build_sparkline_svg(_series("c2_active_count", kpis.c2_active_count)),
            "map_svg": _build_world_map_svg(c2_items, _malware_color_by_name),
            "malware_family_breakdown": _mf_breakdown,
            "malware_family_chart": _build_mini_bar_chart_svg(_mf_breakdown, "malware_family"),
            "top_asn": _asn_breakdown,
            "top_asn_chart": _build_mini_bar_chart_svg(_asn_breakdown, "asn"),
            "open_ports_breakdown": _ports_breakdown,
            "open_ports_chart": _build_mini_bar_chart_svg(_ports_breakdown, "port"),
            "cross_confirmed": c2_cross_confirmed,
            # Mappings nom -> couleur (mêmes valeurs que le champ "color" des breakdowns
            # ci-dessus) — consommés directement par le template pour colorer les cellules
            # "Malware family"/"ASN" du tableau, cf. CDC Phase B point 8.
            "malware_color_by_name": _malware_color_by_name,
            "asn_color_by_name": _asn_color_by_name,
        },
        "malicious_urls": {
            "online_count": kpis.malicious_url_count,
            "trend_pct": kpis.malicious_url_trend_pct,
            "items": malicious_url_items,
            "sparkline": _build_sparkline_svg(_series("malicious_url_count", kpis.malicious_url_count)),
            "trend_chart": _build_area_chart_svg(_series("malicious_url_count", kpis.malicious_url_count)),
            "threat_type_breakdown": (
                _tt_breakdown := _chip_breakdown(malicious_url_items, "threat_type", "threat_type", _TOP_N_COUNTRIES)
            ),
            "threat_type_chart": _build_mini_bar_chart_svg(_tt_breakdown, "threat_type"),
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
            "sources_by_category": _sources_by_category(_SOURCES),
            "pipeline_duration_seconds": round(pipeline_duration_seconds, 2),
        },
    }
