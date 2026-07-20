from __future__ import annotations

import math
import re
from datetime import datetime

import polars as pl

from beesint_threat_report.load.countries import country_name
from beesint_threat_report.load.cwe_names import cwe_name
from beesint_threat_report.load.world_borders_path import WORLD_BORDERS_PATH_D
from beesint_threat_report.load.world_map_path import WORLD_LANDMASS_PATH_D
from beesint_threat_report.transform.breaches import severity_bucket
from beesint_threat_report.transform.kpis import ReportKpis

_TOP_N_COUNTRIES = 10
_URL_TRUNCATE_LEN = 80

# Icônes par secteur (Ransomware Watch — "targeted sectors this week") — mapping partagé avec le
# frontend (beesint-frontend, TS mirror de ce dict) pour rester visuellement cohérent PDF<->web.
# Emoji testés au rendu WeasyPrint réel (Plus Jakarta Sans/JetBrains Mono n'embarquent pas de
# glyphes emoji couleur, mais WeasyPrint retombe sur les emoji monochromes du système de fonts
# fallback disponibles sur le runner GitHub Actions — rendu confirmé non-vide). À étendre au fil
# des nouveaux libellés de secteur observés dans les données ransomware.live (pas de liste
# exhaustive garantie côté source).
SECTOR_ICONS: dict[str, str] = {
    "Finance": "\U0001f4b0",
    "Healthcare": "\U0001f3e5",
    "Government": "\U0001f3db️",
    "Education": "\U0001f393",
    "Energy": "⚡",
    "Retail": "\U0001f6d2",
    "Manufacturing": "\U0001f3ed",
    "Tech": "\U0001f4bb",
    "Telecom": "\U0001f4e1",
    "Transportation": "\U0001f69a",
    "Legal": "⚖️",
    "Media": "\U0001f4f0",
    "Hospitality": "\U0001f3e8",
    "Real Estate": "\U0001f3e2",
    "unknown": "❓",
}

_HTML_TAG_RE = re.compile(r"<[^>]+>")


def _strip_html(text: str) -> str:
    """HIBP's `Description` field routinely embeds raw `<a href=...>` markup (links to the
    source article/forum). Autoescape alone would just show the escaped tag soup as literal
    text — this strips it entirely so the description reads as clean prose. Must run BEFORE
    any char-count truncation: truncating raw HTML by character count can cut a tag in half,
    leaving an unclosed element that swallows the rest of the document (confirmed root cause
    of the "everything after Breaches This Week turns into an underlined reddit link" bug)."""
    return re.sub(r"\s+", " ", _HTML_TAG_RE.sub("", text)).strip()


def _truncate_at_word(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    truncated = text[: max_len - 3].rsplit(" ", 1)[0]
    return truncated + "..."


# "category" groupe les sources pour la section Pipeline Lineage & Source Attribution (refonte
# liste sobre, pas de card look — cf. _lineage.html.j2) : 4 groupes fixes couvrant les 4 grandes
# familles de données du rapport (CVE/KEV, C2 infra + son enrichissement IP, URLs malveillantes,
# géolocalisation). Shodan/Spamhaus/GreyNoise classées "C2" : ce sont des sources d'enrichissement
# des mêmes IP C2 (cf. CDC "Data source integration rule"), pas une catégorie à part.
_SOURCES = [
    {
        "name": "NVD (National Vulnerability Database)",
        "url": "https://nvd.nist.gov/",
        "note": "Public domain — NIST.",
        "category": "CVE / KEV",
    },
    {
        "name": "CISA Known Exploited Vulnerabilities (KEV)",
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "note": "Public domain — CISA.",
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
        "note": "IP geolocation, non-commercial use.",
        "category": "Geolocation",
    },
    {
        "name": "Shodan InternetDB",
        "url": "https://internetdb.shodan.io/",
        "note": "Public domain — free, no API key.",
        "category": "C2 Infrastructure",
    },
    {
        "name": "Spamhaus DROP/EDROP",
        "url": "https://www.spamhaus.org/drop/",
        "note": "Public CIDR lists — non-commercial use.",
        "category": "C2 Infrastructure",
    },
    {
        "name": "GreyNoise Community API",
        "url": "https://viz.greynoise.io/",
        "note": "Free tier, API key required — IP classification.",
        "category": "C2 Infrastructure",
    },
    {
        "name": "OpenPhish",
        "url": "https://openphish.com/",
        "note": "Public community feed — free, no API key.",
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
_EPSS_SCATTER_MIN_ITEMS = 5  # sous ce seuil, un scatter serait aussi peu lisible qu'un chart à
# 1-2 points — même discipline que _HISTOGRAM_MIN_ITEMS, un badge par ligne suffit en dessous.
_EPSS_LOW_COLOR = "#22C55E"  # --color-success
_EPSS_MED_COLOR = "#F59E0B"  # --color-warning
_EPSS_HIGH_COLOR = "#EF4444"  # --color-error

_HISTOGRAM_MIN_ITEMS = 6  # sous ce seuil, un histogramme par bin serait aussi peu lisible que
# les bar-charts count=1 déjà bannis ailleurs (vendors/CWE) — cf. philosophie du fichier.
# Frontière C2 sur la carte (nouveau path statique, cf. world_borders_path.py) — ton neutre
# discret, distinct à la fois de _MAP_LAND_COLOR (masse continentale) et des couleurs de rang
# ci-dessous (dots), pour rester un repère de fond plutôt qu'une donnée.
_MAP_BORDER_COLOR = "#4A6080"  # --color-entity-other, réutilisé comme gris-bleu neutre

# Palette catégorielle "rang -> couleur", tokens --color-entity-* du design system frontend (cf.
# CLAUDE.md racine, ENTITY_COLORS dans beesint-frontend/src/types/index.ts) — copiés ici au même
# titre que les autres tokens dupliqués en tête de report.css (repos indépendants, à
# resynchroniser manuellement si la DA change côté frontend). Défaut de _attach_rank_colors ci-
# dessous — reste utilisée par threat_type_breakdown (malicious URLs) et tout futur breakdown qui
# n'a pas besoin d'une palette dédiée.
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

# C2 infra redesign (CDC Phase P4) — "color by IP" : chaque ligne IP (carte + colonne IP du
# tableau) porte SA PROPRE couleur de rang, plus par malware_family. Palette large/générique
# (c'est le point le plus visible de la section) — distincte des 3 palettes dédiées ci-dessous
# pour qu'un point sur la carte ne soit jamais confondu avec une couleur de breakdown.
_IP_COLOR_TOKENS = [
    "#0EA5E9",  # --color-primary
    "#F59E0B",  # --color-accent-gold
    "#22C55E",  # --color-success
    "#A855F7",  # --color-entity-organization
    "#EC4899",  # --color-entity-certificate
    "#06B6D4",  # --color-entity-username
    "#EF4444",  # --color-error
    "#38BDF8",  # --color-primary-light
    "#F97316",  # orange — hors palette entité, hue additionnelle pour les 10 rangs
    "#84CC16",  # lime — idem
]
# 3 palettes dédiées par dimension (malware family / ASN / ports) — teintes distinctes entre
# elles ET de _IP_COLOR_TOKENS ci-dessus, pour qu'aucune des 4 dimensions colorées de cette
# section ne se confonde visuellement avec une autre.
_MALWARE_FAMILY_COLOR_TOKENS = [  # chauds (rouge/orange/ambre)
    "#EF4444",
    "#F97316",
    "#F59E0B",
    "#FB923C",
    "#FBBF24",
    "#FCA5A5",
    "#DC2626",
    "#EA580C",
    "#D97706",
    "#FDBA74",
]
_ASN_COLOR_TOKENS = [  # froids (bleu/cyan)
    "#0EA5E9",
    "#38BDF8",
    "#06B6D4",
    "#22D3EE",
    "#0284C7",
    "#67E8F9",
    "#0369A1",
    "#7DD3FC",
    "#155E75",
    "#164E63",
]
_PORT_COLOR_TOKENS = [  # violet/magenta
    "#A855F7",
    "#EC4899",
    "#C084FC",
    "#D946EF",
    "#F472B6",
    "#9333EA",
    "#DB2777",
    "#E879F9",
    "#7E22CE",
    "#BE185D",
]

# Formes de marqueur pour la carte C2 (points), cycle déterministe sur le tri alphabétique des
# malware_family (pas par rang de fréquence) — stable au sein d'un run, cohérent run-à-run pour
# les familles récurrentes, sans état persisté entre runs (cf. _family_shape_map).
_MARKER_SHAPES = ["circle", "triangle", "square", "diamond", "star", "cross"]
# Couleur neutre pour les icônes de la légende de formes (map-legend) — la légende porte
# uniquement la forme, pas une couleur par famille (c'est l'IP qui est colorée maintenant, pas la
# famille), donc ses icônes restent grises plutôt que d'emprunter une couleur qui suggérerait à
# tort un mapping couleur<->famille.
_LEGEND_SHAPE_COLOR = _TEXT_MUTED_COLOR


def _rank_color(rank: int, palette: list[str] = _RANK_COLOR_TOKENS) -> str:
    return palette[rank % len(palette)]


def _attach_rank_colors(rows: list[dict], palette: list[str] = _RANK_COLOR_TOKENS) -> list[dict]:
    """Attache `color` (palette donnée, défaut _RANK_COLOR_TOKENS, index = position dans `rows`)
    à une liste déjà triée par _chip_breakdown/_open_ports_breakdown (rang 0 = valeur la plus
    fréquente). Retourne une NOUVELLE liste de dicts (jamais de mutation en place — ces rows
    peuvent être réutilisées telles quelles ailleurs)."""
    return [{**row, "color": _rank_color(i, palette)} for i, row in enumerate(rows)]


def _family_shape_map(c2_items: list[dict]) -> dict[str, str]:
    """Assigne une forme fixe par malware_family : tri alphabétique (pas par rang de fréquence,
    qui varierait d'un run à l'autre pour la même famille) puis cycle sur _MARKER_SHAPES —
    déterministe et stable, sans état persisté entre runs."""
    families = sorted({item["malware_family"] for item in c2_items if item.get("malware_family")})
    return {family: _MARKER_SHAPES[i % len(_MARKER_SHAPES)] for i, family in enumerate(families)}


def _polygon_points(cx: float, cy: float, r: float, sides: int, start_deg: float = -90) -> str:
    points = []
    for i in range(sides):
        angle = math.radians(start_deg + i * 360 / sides)
        points.append(f"{cx + r * math.cos(angle):.1f},{cy + r * math.sin(angle):.1f}")
    return " ".join(points)


def _star_points(cx: float, cy: float, r_outer: float, r_inner: float, spikes: int) -> str:
    points = []
    for i in range(spikes * 2):
        r = r_outer if i % 2 == 0 else r_inner
        angle = math.radians(-90 + i * 360 / (spikes * 2))
        points.append(f"{cx + r * math.cos(angle):.1f},{cy + r * math.sin(angle):.1f}")
    return " ".join(points)


def _build_marker_svg(shape: str, x: float, y: float, color: str, r: float = 3.6, include_halo: bool = True) -> str:
    """Un marqueur de carte (point C2) dans une forme déterministe par malware_family (cf.
    _family_shape_map). Halo translucide commun à toutes les formes (glow discret autour du
    point) + forme pleine dessinée par-dessus pour rester distinguable à petite taille.
    r=3.6 (halo r+1.8, opacity réduite) : plus fin/lisible que l'ancien r=4.5+halo r+3 — la
    légende (`include_halo=False`) n'a pas besoin du halo (pas un point sur fond de carte),
    juste la forme. Fallback "circle" si la forme est inconnue."""
    halo = (
        f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r + 1.8:.1f}" fill="{color}" fill-opacity="0.16"/>'
        if include_halo
        else ""
    )
    if shape == "square":
        side = r * 1.6
        mark = f'<rect x="{x - side / 2:.1f}" y="{y - side / 2:.1f}" width="{side:.1f}" height="{side:.1f}" fill="{color}"/>'
    elif shape == "triangle":
        mark = f'<polygon points="{_polygon_points(x, y, r * 1.35, 3)}" fill="{color}"/>'
    elif shape == "diamond":
        mark = f'<polygon points="{_polygon_points(x, y, r * 1.35, 4)}" fill="{color}"/>'
    elif shape == "star":
        mark = f'<polygon points="{_star_points(x, y, r * 1.5, r * 0.55, 4)}" fill="{color}"/>'
    elif shape == "cross":
        stroke_w = r * 0.85
        mark = (
            f'<line x1="{x - r * 1.3:.1f}" y1="{y:.1f}" x2="{x + r * 1.3:.1f}" y2="{y:.1f}" '
            f'stroke="{color}" stroke-width="{stroke_w:.1f}" stroke-linecap="round"/>'
            f'<line x1="{x:.1f}" y1="{y - r * 1.3:.1f}" x2="{x:.1f}" y2="{y + r * 1.3:.1f}" '
            f'stroke="{color}" stroke-width="{stroke_w:.1f}" stroke-linecap="round"/>'
        )
    else:  # "circle" (défaut/fallback)
        mark = f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r:.1f}" fill="{color}"/>'
    return halo + mark


def _build_shape_icon_svg(shape: str, size: int = 11) -> str:
    """Icône autonome (map-legend, formes seules — pas de couleur par famille, cf.
    _LEGEND_SHAPE_COLOR) — réutilise _build_marker_svg, pas de réimplémentation CSS séparée.
    Pas de halo ici (`include_halo=False`) : sur fond texte (pas la carte), un halo ne fait que
    rendre la forme floue à cette petite taille."""
    cx = cy = size / 2
    marker = _build_marker_svg(shape, cx, cy, _LEGEND_SHAPE_COLOR, r=size * 0.32, include_halo=False)
    return f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" class="shape-icon">{marker}</svg>'


def _build_stacked_bar_svg(rows: list[dict], width: int = 320, height: int = 22) -> str | None:
    """Barre horizontale unique empilée à 100% par proportion (pct_of_total) — remplace
    _build_mini_bar_chart_svg pour les 3 breakdowns C2 (malware family/ASN/ports uniquement,
    _build_mini_bar_chart_svg reste utilisée telle quelle pour threat_type_chart/impact_chart).
    Plus compact qu'un bar-chart par ligne — la légende (couleur/nom/count) vit en HTML à côté
    (template, classes .chart-legend existantes), pas dans le SVG, même séparation que le donut
    de sévérité CVE (_build_severity_donut_svg + .chart-legend en template)."""
    if not rows:
        return None
    total_pct = sum(row["pct_of_total"] for row in rows) or 100.0
    x = 0.0
    segments = []
    for row in rows:
        seg_width = (row["pct_of_total"] / total_pct) * width
        if seg_width <= 0:
            continue
        color = row.get("color") or _HISTOGRAM_COLOR
        segments.append(f'<rect x="{x:.1f}" y="0" width="{seg_width:.1f}" height="{height}" fill="{color}"/>')
        x += seg_width
    return (
        f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" class="stacked-bar">'
        + "".join(segments)
        + "</svg>"
    )


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
    items: list[dict], family_shapes: dict[str, str] | None = None, width: int = 480, height: int = 220
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

    Couleur par point = item["color"] (couleur de rang par IP, cf. _attach_rank_colors avec
    _IP_COLOR_TOKENS — `items` doit donc déjà être passé pré-coloré). Forme par point =
    family_shapes.get(item["malware_family"]) (cf. _family_shape_map), fallback "circle" si
    famille inconnue/mapping absent — remplace l'ancien dot_color_by_malware (couleur par
    malware_family), cf. CDC Phase P4 "color by IP, shape by malware family"."""
    family_shapes = family_shapes or {}
    points = [
        (
            item["lon"],
            item["lat"],
            item.get("color", _MAP_DOT_COLOR),
            family_shapes.get(item.get("malware_family"), "circle"),
        )
        for item in items
        if item.get("lat") is not None and item.get("lon") is not None
    ]
    if not points:
        return None

    def _project(lon: float, lat: float) -> tuple[float, float]:
        return (lon + 180) / 360 * width, (90 - lat) / 180 * height

    dots = []
    for lon, lat, color, shape in points:
        x, y = _project(lon, lat)
        dots.append(_build_marker_svg(shape, x, y, color))

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


def _build_multi_donut_svg(
    segments: list[tuple[int, str]], center_label: str, size: int = 130, stroke: int = 16
) -> str | None:
    """Généralisation N-segments de _build_severity_donut_svg ci-dessus, SANS y toucher (celle-ci
    reste dédiée à ses 2 segments fixes CVE critical/high, déjà testée) — pour la section Breaches
    (jusqu'à 4 segments de sévérité CRITICAL/HIGH/MEDIUM/LOW, cf. CDC Phase P5).
    `segments` : liste de (count, color) dans l'ordre d'affichage voulu — l'ordre de sévérité est
    fixe/sémantique, pas un tri par fréquence comme _attach_rank_colors."""
    total = sum(count for count, _ in segments)
    if total <= 0:
        return None
    radius = (size - stroke) / 2
    circumference = 2 * math.pi * radius
    cx = cy = size / 2

    arcs = []
    offset = 0.0
    for count, color in segments:
        if count <= 0:
            continue
        seg_len = circumference * (count / total)
        arcs.append(
            f'<circle cx="{cx}" cy="{cy}" r="{radius}" fill="none" stroke="{color}" '
            f'stroke-width="{stroke}" stroke-dasharray="{seg_len:.1f} {circumference:.1f}" '
            f'stroke-dashoffset="-{offset:.1f}" transform="rotate(-90 {cx} {cy})"/>'
        )
        offset += seg_len

    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" class="severity-donut">'
        + "".join(arcs)
        + f'<text x="{cx}" y="{cy - 3}" text-anchor="middle" fill="{_TEXT_BODY_COLOR}" '
        f'font-family="JetBrains Mono, monospace" font-size="22" font-weight="700">{total}</text>'
        f'<text x="{cx}" y="{cy + 15}" text-anchor="middle" fill="{_TEXT_MUTED_COLOR}" '
        f'font-family="JetBrains Mono, monospace" font-size="8" letter-spacing="1">{center_label}</text>'
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


def epss_band_color(epss_score: float | None) -> str:
    """Bande de couleur EPSS partagée entre le badge (sous le seuil scatter) et les points du
    scatter lui-même — un seul vocabulaire de couleur pour la même donnée, jamais deux échelles
    différentes selon le composant. <0.1 = bruit de fond, 0.1-0.5 = à surveiller, >0.5 = priorité
    de patch réelle (pas juste sévère — probablement exploité)."""
    if epss_score is None:
        return _TEXT_MUTED_COLOR
    if epss_score > 0.5:
        return _EPSS_HIGH_COLOR
    if epss_score > 0.1:
        return _EPSS_MED_COLOR
    return _EPSS_LOW_COLOR


def _build_cvss_epss_scatter_svg(
    critical_items: list[dict],
    trend_series: list[float] | None = None,
    width: int = 280,
    height: int = 140,
    sparkline_w: int = 70,
) -> str | None:
    """CVSS (sévérité) x EPSS (probabilité d'exploitation réelle) — un CVE en haut à droite est la
    vraie priorité de la semaine, un CVSS 9.8 rarement exploité (bas) compte moins qu'un 7.2 très
    probablement ciblé (haut). Uniquement sur des scores réels des deux côtés — jamais de point
    fabriqué. Sous _EPSS_SCATTER_MIN_ITEMS, retourne None (le template retombe sur un badge par
    ligne, même discipline que _build_cvss_histogram_svg). Pas de width/height fixes sur la racine
    <svg> (seulement viewBox) — .chart-card svg.epss-scatter pilote la largeur réelle via CSS,
    même fix que .map-frame svg (cf. CLAUDE.md "WeasyPrint 62.3"). `sparkline_w` réserve une
    colonne à droite du scatter pour la mini-tendance 4-runs (trend_series), séparée par une
    ligne verticale — élargit le viewBox plutôt que de superposer sur le plot."""
    points = [
        (item["cvss_score"], item["epss_score"], item["cve_id"])
        for item in critical_items
        if item.get("cvss_score") is not None and item.get("epss_score") is not None
    ]
    if len(points) < _EPSS_SCATTER_MIN_ITEMS:
        return None

    has_sparkline = trend_series is not None and len(trend_series) >= 2
    scatter_w = width + (sparkline_w if has_sparkline else 0)
    left_margin, bottom_margin, top_margin, right_margin = 30, 20, 10, 10
    plot_w = width - left_margin - right_margin
    plot_h = height - top_margin - bottom_margin

    def _project(cvss: float, epss: float) -> tuple[float, float]:
        x = left_margin + (cvss / 10) * plot_w
        y = top_margin + (1 - epss) * plot_h
        return x, y

    axis = (
        f'<line x1="{left_margin}" y1="{height - bottom_margin}" x2="{width - right_margin}" '
        f'y2="{height - bottom_margin}" stroke="{_MAP_BORDER_COLOR}" stroke-width="1"/>'
        f'<line x1="{left_margin}" y1="{top_margin}" x2="{left_margin}" y2="{height - bottom_margin}" '
        f'stroke="{_MAP_BORDER_COLOR}" stroke-width="1"/>'
        f'<text x="{left_margin}" y="{height - 4}" fill="{_TEXT_MUTED_COLOR}" '
        f'font-family="JetBrains Mono, monospace" font-size="7">CVSS 0</text>'
        f'<text x="{width - right_margin}" y="{height - 4}" text-anchor="end" fill="{_TEXT_MUTED_COLOR}" '
        f'font-family="JetBrains Mono, monospace" font-size="7">10</text>'
        # Label Y (EPSS) manquant jusqu'ici — seul l'axe X était nommé. Vertical, ancré en haut de
        # l'axe, rotation -90° autour de son propre point d'ancrage.
        f'<text x="{left_margin - 6}" y="{top_margin + 4}" fill="{_TEXT_MUTED_COLOR}" '
        f'font-family="JetBrains Mono, monospace" font-size="7" text-anchor="end" '
        f'transform="rotate(-90 {left_margin - 6} {top_margin + 4})">EPSS 1.0</text>'
        f'<text x="{left_margin - 6}" y="{height - bottom_margin}" fill="{_TEXT_MUTED_COLOR}" '
        f'font-family="JetBrains Mono, monospace" font-size="7" text-anchor="end">0</text>'
    )
    dots = []
    for cvss, epss_score, _cve_id in points:
        x, y = _project(cvss, epss_score)
        color = epss_band_color(epss_score)
        dots.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4.5" fill="{color}" fill-opacity="0.85"/>')

    sparkline = ""
    if has_sparkline:
        spark_x0 = width + 12
        spark_x1 = scatter_w - 6
        spark_lo, spark_hi = min(trend_series), max(trend_series)
        spark_span = (spark_hi - spark_lo) or 1
        n = len(trend_series)
        spark_pts = [
            (
                spark_x0 + (i / (n - 1)) * (spark_x1 - spark_x0),
                top_margin + (1 - (v - spark_lo) / spark_span) * plot_h,
            )
            for i, v in enumerate(trend_series)
        ]
        path = " ".join(f"{'M' if i == 0 else 'L'}{x:.1f},{y:.1f}" for i, (x, y) in enumerate(spark_pts))
        last_x, last_y = spark_pts[-1]
        sparkline = (
            f'<line x1="{width}" y1="{top_margin}" x2="{width}" y2="{height - bottom_margin}" '
            f'stroke="{_MAP_BORDER_COLOR}" stroke-width="1"/>'
            f'<text x="{spark_x0}" y="{top_margin - 2}" fill="{_TEXT_MUTED_COLOR}" '
            f'font-family="JetBrains Mono, monospace" font-size="6">4-run trend</text>'
            f'<path d="{path}" fill="none" stroke="{_MAP_BORDER_COLOR}" stroke-width="1.2"/>'
            f'<circle cx="{last_x:.1f}" cy="{last_y:.1f}" r="2.5" fill="{_TEXT_MUTED_COLOR}"/>'
        )

    return (
        f'<svg viewBox="0 0 {scatter_w} {height}" class="epss-scatter">' + axis + "".join(dots) + sparkline + "</svg>"
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
        # _format_breach_count (K/M/B) réutilisée ici bien que nommée pour les breaches : reste
        # un no-op d'affichage pour les petits comptes existants (malware/threat_type, <1000,
        # rendus tels quels) et corrige un vrai débordement du <text> hors du viewBox (confirmé
        # au rendu réel) pour les gros comptes de comptes exposés (impact_chart, Phase P5) — un
        # compte à 8 chiffres à cette position x dépassait la largeur du SVG.
        bars.append(
            f'<text x="{label_w + bar_w + 6:.1f}" y="{y + bar_h / 2 + 3:.1f}" fill="{_TEXT_BODY_COLOR}" '
            f'font-family="JetBrains Mono, monospace" font-size="8.5">{_format_breach_count(row[count_key])}</text>'
        )

    return (
        f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" class="mini-bar-chart">'
        + "".join(bars)
        + "</svg>"
    )


_SECTOR_CHART_MIN_ITEMS = 3  # même discipline que _PORT_BREAKDOWN_MIN_IPS : sous 3 secteurs, un chip-
# list dit déjà tout ce qu'un graphe dirait, cf. _HISTOGRAM_MIN_ITEMS.


def _build_sector_bar_chart_svg(
    rows: list[dict], label_key: str, count_key: str = "count", width: int = 320, row_height: int = 22
) -> str | None:
    """Bar chart horizontal pour "Targeted sectors this week" (Ransomware Watch) — remplace
    l'ancien lollipop chart (choix utilisateur confirmé : mismatch relevé entre la description
    "gauge" et le code réel, l'utilisateur a tranché pour un bar chart classique plutôt que de
    garder le lollipop ou d'ajouter un gauge). Rang + icône secteur (SECTOR_ICONS) préfixés en
    colonne dédiée à gauche du label plutôt que concaténés dans le texte — évite toute troncature
    du glyphe emoji par la coupe `[:N]` du label."""
    if len(rows) < _SECTOR_CHART_MIN_ITEMS:
        return None

    max_count = max(row[count_key] for row in rows) or 1
    rank_w = 14
    icon_w = 16
    label_w = 96
    plot_w = width - rank_w - icon_w - label_w - 34
    height = row_height * len(rows) + 8

    bars = []
    for i, row in enumerate(rows):
        y = 8 + i * row_height
        bar_h = row_height * 0.55
        bar_y = y + (row_height - bar_h) / 2
        bar_w = max((row[count_key] / max_count) * plot_w, 2)
        color = row.get("color") or _HISTOGRAM_COLOR
        icon = SECTOR_ICONS.get(str(row[label_key]), SECTOR_ICONS["unknown"])
        label = str(row[label_key])[:14]
        text_y = y + row_height / 2 + 3
        bars.append(
            f'<text x="0" y="{text_y:.1f}" fill="{_TEXT_MUTED_COLOR}" '
            f'font-family="JetBrains Mono, monospace" font-size="8.5">{i + 1}</text>'
        )
        bars.append(f'<text x="{rank_w}" y="{text_y:.1f}" font-size="9.5">{icon}</text>')
        bars.append(
            f'<text x="{rank_w + icon_w}" y="{text_y:.1f}" fill="{_TEXT_MUTED_COLOR}" '
            f'font-family="JetBrains Mono, monospace" font-size="8.5">{label}</text>'
        )
        bar_x = rank_w + icon_w + label_w
        bars.append(
            f'<rect x="{bar_x}" y="{bar_y:.1f}" width="{bar_w:.1f}" height="{bar_h:.1f}" rx="2" fill="{color}"/>'
        )
        bars.append(
            f'<text x="{bar_x + bar_w + 6:.1f}" y="{text_y:.1f}" fill="{_TEXT_BODY_COLOR}" '
            f'font-family="JetBrains Mono, monospace" font-size="8.5">{row[count_key]}</text>'
        )

    return f'<svg viewBox="0 0 {width} {height}" class="sector-bar-chart">' + "".join(bars) + "</svg>"


def _ransomware_watch_context(ransomware_watch: dict | None, sources_status: dict[str, str]) -> dict:
    """Construit la section template-ready Ransomware Watch depuis le dict brut assemblé par
    orchestrate.py (kpis/groups/sector_breakdown). `enabled=False` (source en échec ou absente)
    masque toute la section côté template plutôt que d'afficher des zéros trompeurs — même pattern
    que threatfox["enabled"] ci-dessus. sparkline par ligne : nombres bruts -> SVG ici (jamais côté
    orchestrate.py/json_writer.py, qui gardent les nombres bruts pour le frontend, cf. CDC)."""
    enabled = sources_status.get("ransomware_live") == "ok"
    if not enabled or not ransomware_watch:
        return {
            "enabled": False,
            "kpis": {},
            "groups": [],
            "sector_breakdown": [],
            "sector_chart": None,
            "sector_sentence": None,
        }

    groups = [
        {**group, "sparkline": _build_sparkline_svg(group.get("sparkline_weekly_counts") or [])}
        for group in ransomware_watch.get("groups", [])
    ]
    sector_rows = _attach_rank_colors(ransomware_watch.get("sector_breakdown", []))
    # Pas de badge de tendance sur le secteur #1 (creative improvement demandée, cf. plan) : la
    # seule donnée historique dispo à ce niveau est runs/index.json (compteurs légers globaux,
    # jamais de détail par secteur — cf. commentaire "index léger vs rapport complet" plus haut).
    # Calculer une vraie tendance par secteur demanderait de relire le report-<run_id>.json complet
    # du run précédent depuis S3, hors périmètre de ce fix ponctuel — skip documenté plutôt que
    # d'inventer un chiffre.
    sector_sentence = None
    if sector_rows:
        top = sector_rows[0]
        sector_sentence = (
            f"{top['sector']} was the most-targeted sector this week, with {top['count']} of "
            f"{sum(r['count'] for r in sector_rows)} tracked victims ({top.get('pct_of_total', 0)}%)."
        )
    return {
        "enabled": True,
        "kpis": ransomware_watch.get("kpis", {}),
        "groups": groups,
        "sector_breakdown": sector_rows,
        "sector_chart": _build_sector_bar_chart_svg(sector_rows, "sector"),
        "sector_sentence": sector_sentence,
    }


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


def _kev_items(kev_df: pl.DataFrame, epss_by_id: dict[str, dict] | None = None) -> list[dict]:
    if kev_df.height == 0:
        return []
    epss_by_id = epss_by_id or {}
    items = []
    for row in kev_df.to_dicts():
        date_added = row.get("date_added")
        epss_row = epss_by_id.get(row["cve_id"])
        items.append(
            {
                "cve_id": row["cve_id"],
                "vendor_project": row.get("vendor_project"),
                "product": row.get("product"),
                "date_added": date_added.isoformat() if hasattr(date_added, "isoformat") else date_added,
                "ransomware_known_use": row.get("known_ransomware_campaign_use") == "Known",
                "epss_score": epss_row["epss_score"] if epss_row else None,
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
            "mitre_techniques": item.get("mitre_techniques") or [],
        }
        for item in top_ips
    ]


def build_malicious_url_items(ranked_urlhaus_df: pl.DataFrame) -> list[dict]:
    if ranked_urlhaus_df.height == 0:
        return []
    items = []
    for row in ranked_urlhaus_df.to_dicts():
        url_full = row["url"]
        url = url_full
        if len(url) > _URL_TRUNCATE_LEN:
            # "..." ASCII plutôt que le glyphe unicode "…" : absent des webfonts embarqués
            # (Syne/PJS/JetBrains Mono, subsets Latin), provoquerait un fallback système
            # (police interdite, cf. lot 5 "aucune police système de fallback").
            url = url[: _URL_TRUNCATE_LEN - 3] + "..."
        date_added = row.get("date_added")
        items.append(
            {
                "url": url,
                "url_full": url_full,
                "threat_type": row.get("threat"),
                "tags": row.get("tags") or [],
                "date_added": date_added.isoformat() if hasattr(date_added, "isoformat") else date_added,
                # ["urlhaus"] par défaut : lignes construites avant le merge PhishTank (ou runs où
                # PhishTank est skip/failed) n'ont jamais de colonne "sources" du tout.
                "sources": row.get("sources") or ["urlhaus"],
            }
        )
    return items


# Breaches This Week (CDC Phase P5) — couleurs fixes par sévérité (ordinal, pas un rang de
# fréquence) : mêmes tokens que les autres usages sémantiques de ce fichier (_DONUT_CRITICAL_COLOR/
# _DONUT_HIGH_COLOR déjà error/warning), étendus à MEDIUM/LOW pour les 4 paliers de severity_bucket.
_BREACH_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
_BREACH_SEVERITY_COLORS = {
    "CRITICAL": "#EF4444",  # --color-error, = _DONUT_CRITICAL_COLOR
    "HIGH": "#F59E0B",  # --color-warning, = _DONUT_HIGH_COLOR
    "MEDIUM": "#0EA5E9",  # --color-primary
    "LOW": "#22C55E",  # --color-success
}
_BREACH_DESC_TRUNCATE_LEN = 140


def _format_breach_count(n: int) -> str:
    """K/M/B — porté de beesint-jobs/jobs/format_c.py::_format_count(). Les comptes de comptes
    exposés HIBP vont couramment dans les dizaines/centaines de millions ; un entier brut sur une
    .kpi-card ne serait pas lisible."""
    if n >= 1_000_000_000:
        return f"{n / 1_000_000_000:.1f}B"
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.0f}K"
    return str(n)


def _breach_severity_breakdown(breach_items: list[dict]) -> list[dict]:
    """Ordre de sévérité fixe (_BREACH_SEVERITY_ORDER), pas un tri par fréquence comme
    _chip_breakdown — CRITICAL doit toujours apparaître avant LOW dans la légende/le donut, même
    si LOW est plus fréquent ce run."""
    if not breach_items:
        return []
    counts: dict[str, int] = dict.fromkeys(_BREACH_SEVERITY_ORDER, 0)
    for item in breach_items:
        counts[item["severity"]] = counts.get(item["severity"], 0) + 1
    total = len(breach_items)
    return [
        {
            "severity": severity,
            "count": counts[severity],
            "pct_of_total": round(counts[severity] / total * 100, 1),
            "color": _BREACH_SEVERITY_COLORS[severity],
        }
        for severity in _BREACH_SEVERITY_ORDER
        if counts[severity] > 0
    ]


def build_breach_items(ranked_breaches: list, breachdirectory_count: int) -> list[dict]:
    """`ranked_breaches` : list[BreachEntry] déjà classé par pwn_count décroissant (cf.
    ranking.rank_top_n_breaches) — pas un DataFrame, même style list-based que ThreatFoxIoc.
    `breachdirectory_count` : cross-check RapidAPI, appliqué uniquement à l'item le plus
    impactant (rang 0, "spotlight") — le cross-check ne porte que sur LA breach la plus
    impactante du run, pas sur toutes (cf. CDC Phase P5)."""
    items = []
    for rank, entry in enumerate(ranked_breaches):
        # strip AVANT troncature : une coupe par nombre de caractères sur du HTML brut peut
        # couper une balise en deux (cf. _strip_html), donc on nettoie d'abord.
        description = _truncate_at_word(_strip_html(entry.description or ""), _BREACH_DESC_TRUNCATE_LEN)
        items.append(
            {
                "name": entry.title or entry.name,
                "hibp_name": entry.name,
                "domain": entry.domain,
                "breach_date": entry.breach_date.isoformat(),
                "added_date": entry.added_date.isoformat(),
                "pwn_count": entry.pwn_count,
                "pwn_count_formatted": _format_breach_count(entry.pwn_count),
                "data_classes": entry.data_classes,
                "severity": severity_bucket(entry.data_classes),
                "is_verified": entry.is_verified,
                "is_sensitive": entry.is_sensitive,
                "description": description,
                "breachdirectory_count": breachdirectory_count if rank == 0 else None,
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
    epss_by_id: dict[str, dict] | None = None,
    mttk_median_days: float | None,
    mttk_sample_size: int,
    kev_remediation_window_days: float | None,
    feodo_df: pl.DataFrame,
    c2_items: list[dict],
    malicious_url_items: list[dict],
    malicious_url_pool_total: int = 0,
    breach_items: list[dict],
    pipeline_duration_seconds: float,
    sources_status: dict[str, str],
    is_cold_start: bool,
    history_entries: list[dict],
    ransomware_watch: dict | None = None,
) -> dict:
    period_start_str = _fmt_date(period_start)
    period_end_str = _fmt_date(period_end)
    generated_at_str = _fmt_date(generated_at)

    def _series(key: str, current: int) -> list[float]:
        return [h[key] for h in history_entries if key in h] + [current]

    threatfox_enabled = sources_status.get("threatfox") == "ok"
    c2_cross_confirmed = _c2_cross_confirmed(c2_items, sources_status)

    # C2 infra redesign (CDC Phase P4) — "color by IP" : chaque ligne IP (carte + colonne IP du
    # tableau) porte sa propre couleur de rang (_IP_COLOR_TOKENS), rang = position dans c2_items
    # (déjà classé, une ligne par IP). Les 3 breakdowns (malware/ASN/ports) gardent chacun leur
    # PROPRE palette dédiée, distincte de celle des IP et des unes des autres — plus de mapping
    # nom -> couleur partagé avec le tableau (les cellules Malware family/ASN redeviennent plates).
    _c2_items_colored = _attach_rank_colors(c2_items, _IP_COLOR_TOKENS)
    _family_shapes = _family_shape_map(c2_items)
    _mf_breakdown = _attach_rank_colors(
        _chip_breakdown(c2_items, "malware_family", "malware_family", _TOP_N_COUNTRIES), _MALWARE_FAMILY_COLOR_TOKENS
    )
    _asn_breakdown = _attach_rank_colors(_chip_breakdown(c2_items, "asn", "asn", _TOP_N_COUNTRIES), _ASN_COLOR_TOKENS)
    _ports_breakdown = _attach_rank_colors(_open_ports_breakdown(c2_items, _TOP_N_COUNTRIES), _PORT_COLOR_TOKENS)
    # Légende de formes (map-legend, template) — icônes SVG pré-rendues (même builder que les
    # points de la carte, cf. _build_shape_icon_svg), triées alphabétiquement comme _family_shapes.
    _family_shape_legend = [
        {"malware_family": family, "icon_svg": _build_shape_icon_svg(shape)} for family, shape in _family_shapes.items()
    ]

    # Breaches This Week (CDC Phase P5) — severity_breakdown en ordre de sévérité fixe (pas de
    # rang de fréquence), impact_chart réutilise _build_mini_bar_chart_svg tel quel (déjà classé
    # par pwn_count décroissant en amont via ranking.rank_top_n_breaches).
    _breach_severity_rows = _breach_severity_breakdown(breach_items)
    _breach_impact_rows = [{"name": item["name"], "count": item["pwn_count"]} for item in breach_items]

    # Réutilisé par le tile Deep-Dive (epss_high_priority_count) ET le sous-titre/mini-trend du
    # scatter CVSS x EPSS ci-dessous — un seul calcul, même définition que orchestrate.py
    # (sum epss_score > 0.5 sur les CVE critiques du run).
    _epss_high_priority_count = sum(1 for c in critical_items if (c.get("epss_score") or 0) > 0.5)
    _prev_epss_high_priority_count = history_entries[-1].get("epss_high_priority_count") if history_entries else None
    _epss_subtitle = f"{_epss_high_priority_count} critical CVEs have EPSS > 50% this week"
    if _prev_epss_high_priority_count is not None:
        _epss_subtitle += f", vs {_prev_epss_high_priority_count} last week"
    _epss_subtitle += ". Top-right = patch first (severe AND likely exploited)."

    return {
        "report": {
            "run_id": run_id,
            "period_start": period_start_str,
            "period_end": period_end_str,
            "generated_at": generated_at_str,
            "kpi_summary": {
                "cve_critical_count": kpis.cve_critical_count,
                "cve_critical_trend_pct": kpis.cve_critical_trend_pct,
                "kev_new_count": kpis.kev_new_count,
                "kev_new_trend_pct": kpis.kev_new_trend_pct,
                "c2_active_count": kpis.c2_active_count,
                "c2_active_trend_pct": kpis.c2_active_trend_pct,
                "malicious_url_count": kpis.malicious_url_count,
                "malicious_url_trend_pct": kpis.malicious_url_trend_pct,
            },
        },
        "executive_summary": _build_executive_summary(kpis, is_cold_start, sources_status, c2_cross_confirmed),
        "deepdive": {
            "mttk_days": kpis.mean_time_to_kev_days,
            "kev_urgent_count": kpis.kev_urgent_count,
            "epss_high_priority_count": _epss_high_priority_count,
            "breaches_new_count": len(breach_items),
            "breaches_total_accounts_exposed": _format_breach_count(sum(item["pwn_count"] for item in breach_items)),
            "ransomware_active_groups_count": kpis.ransomware_active_groups_count,
            "ransomware_active_groups_trend_pct": kpis.ransomware_active_groups_trend_pct,
            "ransomware_victim_count": kpis.ransomware_victim_count,
            "ransomware_victim_count_trend_pct": kpis.ransomware_victim_count_trend_pct,
            "ransomware_sparkline": _build_sparkline_svg(
                _series("ransomware_victim_count", kpis.ransomware_victim_count)
            ),
            "threatfox_families_count": kpis.threatfox_malware_families_count,
            "threatfox_families_trend_pct": kpis.threatfox_malware_families_trend_pct,
            "threatfox_sparkline": _build_sparkline_svg(
                _series("threatfox_malware_families_count", kpis.threatfox_malware_families_count)
            ),
        },
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
            "cvss_epss_scatter": _build_cvss_epss_scatter_svg(
                critical_items, trend_series=_series("epss_high_priority_count", _epss_high_priority_count)[-4:]
            ),
            "cvss_epss_subtitle": _epss_subtitle,
        },
        "kev": {
            "new_count": kpis.kev_new_count,
            "trend_pct": kpis.kev_new_trend_pct,
            "urgent_count": kpis.kev_urgent_count,
            "items": _kev_items(kev_df, epss_by_id),
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
            # Toujours peuplé dès qu'il y a >= 1 entrée KEV ce run (pas limité aux CVE joints
            # NVD/KEV de la même semaine comme le gauge ci-dessus) — cf. transform/mttk.py
            # compute_mean_remediation_window_days, CDC Phase P3.
            "remediation_window_days": kev_remediation_window_days,
            # Pas de tendance semaine-sur-semaine ici : contrairement aux 4 KPI de l'Executive
            # Summary (1e), ReportKpis n'a pas de mean_time_to_kev_days_trend_pct et run_entry ne
            # persiste pas ce champ dans runs/index.json — l'ajouter demanderait de nouvelles
            # colonnes historiques, hors périmètre de ce fix de layout ponctuel. Phrase purement
            # descriptive du run courant, pas de comparaison fabriquée.
            "trend_sentence": (
                f"Critical vulnerabilities took an average of {kpis.mean_time_to_kev_days:.1f} days "
                f"to go from public disclosure to confirmed active exploitation this run — CISA's own "
                f"remediation deadline for this week's KEV additions currently averages "
                f"{kev_remediation_window_days:.1f} days."
                if kpis.mean_time_to_kev_days is not None and kev_remediation_window_days is not None
                else None
            ),
        },
        "c2": {
            "active_count": kpis.c2_active_count,
            "trend_pct": kpis.c2_active_trend_pct,
            # Coloré par IP (rang), plus par malware_family — colonne IP du tableau + points de
            # carte partagent cette même couleur (cf. CDC Phase P4). ASN/Malware family
            # redeviennent des colonnes plates dans le tableau (couleur portée par leurs propres
            # breakdowns ci-dessous uniquement, pas par le tableau).
            "items": _c2_items_colored,
            "sparkline": _build_sparkline_svg(_series("c2_active_count", kpis.c2_active_count)),
            "map_svg": _build_world_map_svg(_c2_items_colored, _family_shapes),
            "malware_family_breakdown": _mf_breakdown,
            "malware_family_chart": _build_stacked_bar_svg(_mf_breakdown),
            "top_asn": _asn_breakdown,
            "top_asn_chart": _build_stacked_bar_svg(_asn_breakdown),
            "open_ports_breakdown": _ports_breakdown,
            "open_ports_chart": _build_stacked_bar_svg(_ports_breakdown),
            "cross_confirmed": c2_cross_confirmed,
            # Légende de formes (map-legend, template) — liste de {malware_family, icon_svg},
            # pas un simple mapping nom->forme, pour rester template-ready comme le reste de ce
            # fichier (gauge_svg/severity_donut/etc. sont déjà des SVG pré-rendus, pas des données
            # brutes recalculées côté Jinja).
            "family_shapes": _family_shape_legend,
        },
        "malicious_urls": {
            "online_count": kpis.malicious_url_count,
            "trend_pct": kpis.malicious_url_trend_pct,
            "items": malicious_url_items,
            "pool_total": malicious_url_pool_total,
            "sparkline": _build_sparkline_svg(_series("malicious_url_count", kpis.malicious_url_count)),
            "trend_chart": _build_area_chart_svg(_series("malicious_url_count", kpis.malicious_url_count)),
            "threat_type_breakdown": (
                _tt_breakdown := _chip_breakdown(malicious_url_items, "threat_type", "threat_type", _TOP_N_COUNTRIES)
            ),
            "threat_type_chart": _build_mini_bar_chart_svg(_tt_breakdown, "threat_type"),
        },
        "breaches": {
            "new_count": len(breach_items),
            "total_accounts_exposed": _format_breach_count(sum(item["pwn_count"] for item in breach_items)),
            "spotlight": breach_items[0] if breach_items else None,
            "severity_breakdown": _breach_severity_rows,
            "severity_donut": _build_multi_donut_svg(
                [(row["count"], row["color"]) for row in _breach_severity_rows], "BREACHES"
            ),
            "impact_chart": _build_mini_bar_chart_svg(_breach_impact_rows, "name"),
        },
        "threatfox": {
            "enabled": threatfox_enabled,
            "families_count": kpis.threatfox_malware_families_count,
            "families_trend_pct": kpis.threatfox_malware_families_trend_pct,
            "sparkline": _build_sparkline_svg(
                _series("threatfox_malware_families_count", kpis.threatfox_malware_families_count)
            ),
        },
        "ransomware_watch": _ransomware_watch_context(ransomware_watch, sources_status),
        "geo": {
            # Step 4 (GeoIP/ASN MVP) : top_asn (C2 infra, ci-dessus) a déjà son bar chart depuis
            # le début — top_countries restait chip-list-only par choix documenté (la plupart des
            # comptes valaient 1, un bar chart de tout-à-1 n'ajoute aucun signal qu'un chiffre ne
            # dit déjà, cf. CLAUDE.md "WeasyPrint 62.3"). _build_mini_bar_chart_svg gate déjà ce
            # cas (rows[0].count == rows[-1].count -> None) — réutiliser cette même fonction ici
            # ajoute un chart UNIQUEMENT quand la distribution a un vrai signal, sans revenir sur
            # la décision documentée pour le cas plat.
            "top_countries": (_top_countries_rows := _geo_top_countries(feodo_df, _TOP_N_COUNTRIES)),
            "top_countries_chart": _build_mini_bar_chart_svg(_top_countries_rows, "country_name"),
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
