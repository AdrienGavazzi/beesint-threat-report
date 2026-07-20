import copy
from pathlib import Path

import jinja2
import pytest
from pypdf import PdfReader

from beesint_threat_report.load.pdf_renderer import _fmt_date_short, render_pdf

try:
    import weasyprint  # noqa: F401

    _WEASYPRINT_AVAILABLE = True
except OSError:
    # Pango/GTK absent (Windows sans MSYS2, cf. CDC §24) — skip plutôt que crash de collecte.
    _WEASYPRINT_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not _WEASYPRINT_AVAILABLE, reason="Pango/GTK indisponible (WeasyPrint ne peut pas charger)"
)

_REPO_ROOT = Path(__file__).resolve().parents[1]
_REPORT_CSS_PATH = _REPO_ROOT / "styles" / "report.css"
_TEMPLATE_DIR = _REPO_ROOT / "templates"


def _render_html(context: dict) -> str:
    """Rend uniquement le HTML (sans WeasyPrint) — pour les assertions sur des détails
    CSS/structure (couleurs inline, classes) que l'extraction de texte PDF ne peut pas observer.
    Réplique la config jinja de pdf_renderer.render_pdf() (StrictUndefined + filtre
    fmt_date_short, réutilisé tel quel plutôt que dupliqué)."""
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(_TEMPLATE_DIR)), undefined=jinja2.StrictUndefined)
    env.filters["fmt_date_short"] = _fmt_date_short
    return env.get_template("report.html.j2").render(**context)


_SECTION_TITLES = [
    "BeeSINT Threat Report",
    "Executive Summary",
    "Executive Deep-Dive",
    "Source Status",
    "Contents",
    "New Critical CVEs",
    "CISA KEV Additions",
    "Mean-Time-to-KEV",
    "Active C2 Infrastructure",
    "Malicious URLs Online",
    "Breaches This Week",
    "Top 10 Countries",
    "Top Vendors",
    "CWE Breakdown",
    "Pipeline Lineage",
]


def minimal_context() -> dict:
    return {
        "report": {
            "run_id": "run-1",
            "period_start": "01 June 2026",
            "period_end": "08 June 2026",
            "generated_at": "08 June 2026",
            "kpi_summary": {
                "cve_critical_count": 2,
                "cve_critical_trend_pct": 12.5,
                "kev_new_count": 1,
                "kev_new_trend_pct": None,
                "c2_active_count": 1,
                "c2_active_trend_pct": -5.0,
                "malicious_url_count": 2,
                "malicious_url_trend_pct": None,
            },
        },
        "executive_summary": "This week, the pipeline tracked 2 new critical CVEs. "
        "1 was added to CISA's Known Exploited Vulnerabilities catalog, including at least "
        "one tied to known ransomware activity. 1 command-and-control server(s) remain "
        "active and 2 malicious URLs were seen online in the monitored feeds.",
        "deepdive": {
            "mttk_days": 4.5,
            "kev_urgent_count": 0,
            "epss_high_priority_count": 1,
            "breaches_new_count": 1,
            "breaches_total_accounts_exposed": "1.2M",
            "ransomware_active_groups_count": 0,
            "ransomware_active_groups_trend_pct": None,
            "ransomware_victim_count": 0,
            "ransomware_victim_count_trend_pct": None,
            "ransomware_sparkline": None,
            "threatfox_families_count": 0,
            "threatfox_families_trend_pct": None,
            "threatfox_sparkline": None,
        },
        "sources_status": [
            {"name": "kev", "status": "ok"},
            {"name": "nvd", "status": "ok"},
        ],
        "cve": {
            "critical_count": 2,
            "critical_trend_pct": 12.5,
            "high_volume_count": 5,
            "critical_items": [
                {
                    "cve_id": "CVE-2026-1",
                    "description": "Example remote code execution vulnerability.",
                    "cvss_score": 9.8,
                    "published_date": "2026-06-02",
                    "vendor": "acme",
                    "epss_score": 0.94,
                    "epss_percentile": 0.99,
                }
            ],
            "sparkline": None,
            "severity_donut": None,
            "cvss_histogram": None,
            "cvss_epss_scatter": None,
            "cvss_epss_subtitle": "1 critical CVEs have EPSS > 50% this week.",
        },
        "kev": {
            "new_count": 1,
            "trend_pct": None,
            "urgent_count": 0,
            "items": [
                {
                    "cve_id": "CVE-2026-1",
                    "vendor_project": "Acme",
                    "product": "Widget",
                    "date_added": "2026-06-03",
                    "ransomware_known_use": True,
                    "epss_score": 0.94,
                }
            ],
            "urgency_flag": True,
            "sparkline": None,
        },
        "mttk": {
            "average_days": 4.5,
            "median_days": 3.0,
            "sample_size": 1,
            "gauge_svg": None,
            "remediation_window_days": 14.0,
            "trend_sentence": "Critical vulnerabilities took an average of 4.5 days to go from public "
            "disclosure to confirmed active exploitation this run — CISA's own remediation deadline for "
            "this week's KEV additions currently averages 14.0 days.",
        },
        "c2": {
            "active_count": 1,
            "trend_pct": None,
            "items": [
                {
                    "ip_address": "203.0.113.10",
                    "country": "United States",
                    "asn": "AS64500 EXAMPLE-AS",
                    "malware_family": "Heodo",
                    "first_seen": "2026-05-01",
                    "last_online": "2026-06-05",
                    "confirmed_by_spamhaus": True,
                    "greynoise_classification": "malicious",
                    # Couleur par rang IP (cf. CDC Phase P4 "color by IP") — consommée par la
                    # colonne IP du tableau (style inline), plus par malware_family/ASN.
                    "color": "#0EA5E9",
                    "mitre_techniques": ["T1071.001", "T1105"],
                }
            ],
            "sparkline": None,
            # SVG minimal non-None : exerce le bloc légende de carte (formes par malware family,
            # cf. CDC Phase P4) dans test_render_pdf_c2_map_legend_shows_shape_icons.
            "map_svg": '<svg viewBox="0 0 10 10" class="world-map"><circle cx="5" cy="5" r="2"/></svg>',
            "malware_family_breakdown": [
                {"malware_family": "Heodo", "count": 1, "pct_of_total": 100.0, "color": "#EF4444"}
            ],
            "malware_family_chart": '<svg class="stacked-bar"></svg>',
            "top_asn": [{"asn": "AS64500 EXAMPLE-AS", "count": 1, "pct_of_total": 100.0, "color": "#38BDF8"}],
            "top_asn_chart": '<svg class="stacked-bar"></svg>',
            "open_ports_breakdown": [{"port": 443, "count": 1, "pct_of_total": 100.0, "color": "#A855F7"}],
            "open_ports_chart": '<svg class="stacked-bar"></svg>',
            "cross_confirmed": {"confirmed": 1, "total": 1},
            # Légende de formes (map-legend, template) — liste template-ready, cf.
            # pdf_context.py::build_pdf_context _family_shape_legend.
            "family_shapes": [{"malware_family": "Heodo", "icon_svg": '<svg class="shape-icon"></svg>'}],
        },
        "malicious_urls": {
            "online_count": 2,
            "trend_pct": None,
            "pool_total": 2,
            "items": [
                {
                    "url": "http://malicious.example.com/payload",
                    "url_full": "http://malicious.example.com/payload",
                    "threat_type": "malware_download",
                    "tags": ["exe", "elf"],
                    "date_added": "2026-06-04",
                    "sources": ["urlhaus", "openphish"],
                }
            ],
            "sparkline": None,
            "trend_chart": None,
            "threat_type_breakdown": [{"threat_type": "malware_download", "count": 1, "pct_of_total": 100.0}],
            "threat_type_chart": None,
        },
        "breaches": {
            "new_count": 1,
            "total_accounts_exposed": "1.2M",
            "spotlight": {
                "name": "ExampleCorp",
                "hibp_name": "ExampleCorp",
                "domain": "example.com",
                "breach_date": "2026-06-01",
                "added_date": "2026-06-05",
                "pwn_count": 1200000,
                "pwn_count_formatted": "1.2M",
                "data_classes": ["Email addresses", "Passwords"],
                "severity": "CRITICAL",
                "is_verified": True,
                "is_sensitive": False,
                "description": "Example breach description.",
                "breachdirectory_count": 3,
            },
            "severity_breakdown": [{"severity": "CRITICAL", "count": 1, "pct_of_total": 100.0, "color": "#EF4444"}],
            "severity_donut": None,
            "impact_chart": None,
        },
        "threatfox": {"enabled": False, "families_count": 0, "families_trend_pct": None, "sparkline": None},
        "ransomware_watch": {
            "enabled": False,
            "kpis": {},
            "groups": [],
            "sector_breakdown": [],
            "sector_chart": None,
            "sector_sentence": None,
        },
        "geo": {
            "top_countries": [
                {"country_name": "United States", "country_code": "US", "count": 3, "pct_of_total": 60.0},
                {"country_name": "Germany", "country_code": "DE", "count": 2, "pct_of_total": 40.0},
            ],
            "top_countries_chart": None,
        },
        "history_chart": {"svg": None, "legend": []},
        "vendors": {"top_items": [{"vendor_name": "acme", "cve_count": 2}]},
        "cwe": {
            "top_items": [{"cwe_id": "CWE-79", "cwe_name": "Cross-Site Scripting", "count": 2, "pct_of_total": 100.0}]
        },
        "lineage": {
            "run_id": "run-1",
            "period_start": "01 June 2026",
            "period_end": "08 June 2026",
            "generated_at": "08 June 2026",
            "sources_by_category": [
                {
                    "category": "CVE / KEV",
                    "sources": [{"name": "NVD", "url": "https://nvd.nist.gov/", "note": "Domaine public."}],
                },
                {
                    "category": "C2 Infrastructure",
                    "sources": [
                        {
                            "name": "abuse.ch FeodoTracker",
                            "url": "https://feodotracker.abuse.ch/",
                            "note": "Data kindly provided by abuse.ch",
                        }
                    ],
                },
            ],
            "pipeline_duration_seconds": 12.3,
        },
    }


def test_render_pdf_minimal_context_produces_valid_pdf(tmp_path):
    output_path = tmp_path / "report.pdf"

    result = render_pdf(minimal_context(), output_path)

    assert result == output_path
    assert output_path.exists()
    assert output_path.stat().st_size > 0
    reader = PdfReader(str(output_path))
    assert len(reader.pages) >= 1


def test_render_pdf_missing_required_key_raises_undefined_error(tmp_path):
    context = minimal_context()
    del context["mttk"]["average_days"]

    with pytest.raises(jinja2.UndefinedError):
        render_pdf(context, tmp_path / "report.pdf")


def test_render_pdf_missing_top_level_section_raises_undefined_error(tmp_path):
    context = minimal_context()
    del context["lineage"]

    with pytest.raises(jinja2.UndefinedError):
        render_pdf(context, tmp_path / "report.pdf")


def test_render_pdf_all_section_titles_present(tmp_path):
    output_path = tmp_path / "report.pdf"
    render_pdf(minimal_context(), output_path)

    reader = PdfReader(str(output_path))
    # `.section-title` est en `text-transform: uppercase` (CSS) — WeasyPrint transforme le
    # texte au rendu, la casse extraite ne correspond plus au texte source du template.
    full_text_upper = "\n".join(page.extract_text() or "" for page in reader.pages).upper()

    for title in _SECTION_TITLES:
        assert title.upper() in full_text_upper, f"section title missing from rendered PDF: {title!r}"


def test_render_pdf_abuse_ch_attribution_on_every_non_cover_page(tmp_path):
    # Cover page (@page :first) intentionally has no recurring footer — margin is 0 for a
    # full-bleed cover, and the @bottom-* content is explicitly cleared there (report.css) so it
    # doesn't paint flush against the physical edge. The attribution still must appear on every
    # other page, which is what this asserts starting from page 2.
    # Footer merge (Phase B point 11): @bottom-left/@bottom-right were merged — abuse.ch is no
    # longer a standalone @bottom-left string, it now lives inside the merged @bottom-right
    # sources list ("Sources: NVD, CISA KEV, ip-api.com, abuse.ch"), so this asserts on that
    # merged string rather than the old standalone one.
    output_path = tmp_path / "report.pdf"
    render_pdf(minimal_context(), output_path)

    reader = PdfReader(str(output_path))
    assert len(reader.pages) >= 2
    for index, page in enumerate(reader.pages[1:], start=1):
        text = page.extract_text() or ""
        assert "abuse.ch" in text, f"missing abuse.ch attribution on page {index}"
        assert "Sources: NVD, CISA KEV, ip-api.com, abuse.ch" in text, (
            f"unexpected merged sources footer on page {index}"
        )


def test_render_pdf_creates_missing_output_directory(tmp_path):
    output_path = tmp_path / "nested" / "dir" / "report.pdf"

    render_pdf(minimal_context(), output_path)

    assert output_path.exists()


def test_render_pdf_does_not_mutate_input_context(tmp_path):
    context = minimal_context()
    snapshot = copy.deepcopy(context)

    render_pdf(context, tmp_path / "report.pdf")

    assert context == snapshot


# ---- Phase B (refonte visuelle) --------------------------------------------------------------


def test_report_css_cover_fills_full_a4_page_height():
    # .cover height:20cm laissait ~9-10cm de la page A4 physique (29.7cm) hors du conteneur —
    # .cover .run-id (position:absolute, bottom:1.4cm) atterrissait ~9cm au-dessus du vrai bas de
    # page. Regression guard direct sur la valeur CSS (non observable via extraction de texte PDF).
    css = _REPORT_CSS_PATH.read_text(encoding="utf-8")
    cover_block = css.split(".cover {", 1)[1].split("}", 1)[0]
    assert "height: 29.7cm;" in cover_block
    assert "20cm" not in cover_block


def test_report_css_kpi_and_chart_cards_use_margin_not_gap():
    # flex-wrap + gap perd silencieusement le gap dès que le wrap force 2+ lignes sur WeasyPrint
    # 62.3 (cf. CLAUDE.md) — .kpi-grid/.chart-row doivent utiliser le pattern margin-sur-la-card
    # (comme .lineage-card historiquement), jamais gap sur le parent.
    css = _REPORT_CSS_PATH.read_text(encoding="utf-8")

    kpi_grid_block = css.split(".kpi-grid {", 1)[1].split("}", 1)[0]
    kpi_card_block = css.split(".kpi-card {", 1)[1].split("}", 1)[0]
    assert "gap:" not in kpi_grid_block
    assert "margin:" in kpi_card_block

    chart_row_block = css.split(".chart-row {", 1)[1].split("}", 1)[0]
    chart_card_block = css.split(".chart-card {", 1)[1].split("}", 1)[0]
    assert "gap:" not in chart_row_block
    assert "margin:" in chart_card_block


def test_report_css_history_and_area_charts_stretch_full_width():
    # Même bug que .map-frame svg (déjà fixé) sur les 2 autres charts pleine largeur — sans cette
    # règle, le run-history/trend chart ne remplit que sa largeur SVG intrinsèque (~320px) au lieu
    # de la largeur réelle de la card.
    css = _REPORT_CSS_PATH.read_text(encoding="utf-8")
    assert "svg.history-line-chart" in css
    assert "svg.area-chart" in css


def test_render_pdf_lineage_sources_grouped_by_category(tmp_path):
    output_path = tmp_path / "report.pdf"
    render_pdf(minimal_context(), output_path)

    reader = PdfReader(str(output_path))
    full_text_upper = "\n".join(page.extract_text() or "" for page in reader.pages).upper()

    # .lineage-group-title est en text-transform:uppercase (CSS), même raison que
    # test_render_pdf_all_section_titles_present pour la casse comparée en upper().
    assert "CVE / KEV" in full_text_upper
    assert "C2 INFRASTRUCTURE" in full_text_upper
    assert "NVD" in full_text_upper
    assert "FEODOTRACKER" in full_text_upper


def test_mttk_template_merges_kpi_tiles_into_single_grid_card():
    # 1n : les 4 tuiles (average/median/sample/remediation) vivent désormais dans UNE seule card
    # (.chart-card contenant un .kpi-grid, 2 tuiles par ligne) à côté de la jauge — plus de 3e
    # colonne séparée (.mttk-kpi-column/.mttk-remediation-card, gap incohérent entre colonnes).
    template_src = (_TEMPLATE_DIR / "partials" / "_mttk.html.j2").read_text(encoding="utf-8")
    assert "mttk-kpi-column" not in template_src
    assert "mttk-remediation-card" not in template_src
    assert 'class="kpi-grid"' in template_src


def test_lineage_template_has_no_card_look():
    # Point 10 : la section lineage ne doit plus utiliser .lineage-grid/.lineage-card (look card) —
    # remplacée par une liste sobre groupée par catégorie.
    template_src = (_TEMPLATE_DIR / "partials" / "_lineage.html.j2").read_text(encoding="utf-8")
    assert "lineage-grid" not in template_src
    assert "lineage-card" not in template_src
    assert "lineage-list" in template_src


def test_render_html_c2_ip_column_colored_asn_and_malware_plain():
    # CDC Phase P4 ("color by IP") : la colonne IP porte désormais la couleur de rang (couleur
    # inline non observable via extraction de texte PDF — assertion sur le HTML brut) ; ASN et
    # Malware family redeviennent des colonnes plates dans le tableau (plus de mapping nom ->
    # couleur partagé avec le tableau).
    html = _render_html(minimal_context())
    assert 'style="color: #0EA5E9;">203.0.113.10</td>' in html
    assert '<td class="mono">AS64500 EXAMPLE-AS</td>' in html
    assert "<td>Heodo</td>" in html


def test_render_html_c2_map_legend_shows_shape_icons_not_color_list():
    # La légende sous la carte porte désormais des formes (icon_svg pré-rendu par famille, cf.
    # pdf_context.py _build_shape_icon_svg) — plus une liste de couleurs, la couleur du point
    # étant maintenant celle de la colonne IP, pas de la famille.
    html = _render_html(minimal_context())
    assert '<svg class="shape-icon">' in html
    assert "Point color matches the IP column" in html


def test_render_html_c2_breakdown_legends_use_their_own_dedicated_palette():
    # Les 3 breakdowns (malware family/ASN/ports) gardent chacun leur propre couleur de rang
    # (palettes dédiées, distinctes de la couleur IP et les unes des autres) dans la légende sous
    # la barre empilée — cf. minimal_context() fixture, 3 couleurs distinctes attendues.
    html = _render_html(minimal_context())
    assert "background:#EF4444" in html  # malware_family_breakdown[0].color
    assert "background:#38BDF8" in html  # top_asn[0].color
    assert "background:#A855F7" in html  # open_ports_breakdown[0].color


def test_c2_table_signals_column_has_no_stray_bullet_character():
    # Point 8 : audit du badge "Signals" — aucun caractère "•" parasite dans le template ou la
    # feuille de style (le seul indicateur visuel voulu est le .source-dot circulaire existant).
    template_src = (_TEMPLATE_DIR / "partials" / "_c2_infra.html.j2").read_text(encoding="utf-8")
    css = _REPORT_CSS_PATH.read_text(encoding="utf-8")
    assert "•" not in template_src
    assert "•" not in css


def test_bee_logo_asset_is_compressed():
    # Point 12 : 620x603px/404KB -> redimensionné ~150px de large. Regression guard simple sur la
    # taille fichier plutôt que sur les dimensions exactes (Pillow non garanti disponible partout).
    asset_path = _TEMPLATE_DIR / "assets" / "bee_yellow_only.png"
    assert asset_path.stat().st_size < 50_000


# ---- Phase P1 (fixes CSS/markup isolés) ------------------------------------------------------


def test_report_css_chart_card_full_matches_chart_card_right_margin():
    # .chart-card--full doit garder la MEME marge droite que .chart-card (16px) pour que le
    # margin-right négatif de .chart-row (fix "cards n'utilisent pas toute la largeur") compense
    # correctement les deux variantes de la même façon et atteigne le vrai bord droit du
    # conteneur (10px était un ajustement ad-hoc pour matcher l'ancien .kpi-grid, lui-même buggé
    # -- désormais corrigé au même endroit, cf. test_report_css_kpi_grid_compensates_last_card_margin).
    css = _REPORT_CSS_PATH.read_text(encoding="utf-8")
    block = css.split(".chart-card--full {", 1)[1].split("}", 1)[0]
    assert "flex: 1 1 100%;" in block
    assert "margin: 0 16px 16px 0;" in block
    row_block = css.split(".chart-row {", 1)[1].split("}", 1)[0]
    assert "margin-right: -16px;" in row_block


def test_report_css_kpi_grid_compensates_last_card_margin():
    # .kpi-grid doit annuler la marge droite de la dernière card de chaque ligne (sinon les
    # cards s'arrêtent 10px avant le bord réel de la card conteneur, cf. plaintes "les cards ne
    # prennent pas toute la largeur" sur MTTK/C2/ThreatFox/Malicious URLs/Breaches).
    css = _REPORT_CSS_PATH.read_text(encoding="utf-8")
    block = css.split(".kpi-grid {", 1)[1].split("}", 1)[0]
    assert "margin-right: -10px;" in block


def test_report_css_donut_row_legend_uses_free_space():
    css = _REPORT_CSS_PATH.read_text(encoding="utf-8")
    donut_row_block = css.split(".donut-row {", 1)[1].split("}", 1)[0]
    assert "justify-content: space-between;" in donut_row_block
    legend_block = css.split(".donut-row .chart-legend {", 1)[1].split("}", 1)[0]
    assert "flex: 1 1 auto;" in legend_block


def test_report_css_value_run_id_displays_full_uuid_on_wide_card():
    # L'ellipsis précédente cachait la moitié de l'UUID (36 caractères) au lieu de le tronquer
    # proprement -- .kpi-card--wide double le flex-basis pour que le run_id complet tienne sans
    # troncature (overflow:visible, plus d'ellipsis).
    css = _REPORT_CSS_PATH.read_text(encoding="utf-8")
    run_id_block = css.split(".kpi-card .value--run-id {", 1)[1].split("}", 1)[0]
    assert "overflow: visible;" in run_id_block
    assert "text-overflow: ellipsis;" not in run_id_block
    wide_block = css.split(".kpi-card--wide {", 1)[1].split("}", 1)[0]
    assert "flex-basis: 260px;" in wide_block

    template_src = (_TEMPLATE_DIR / "partials" / "_lineage.html.j2").read_text(encoding="utf-8")
    assert "kpi-card--wide" in template_src


def test_malicious_urls_template_uses_chart_card_full_class_not_inline_style():
    template_src = (_TEMPLATE_DIR / "partials" / "_malicious_urls.html.j2").read_text(encoding="utf-8")
    assert "chart-card--full" in template_src
    assert "flex-basis: 100%" not in template_src


def test_lineage_template_uses_value_run_id_class_not_inline_style():
    template_src = (_TEMPLATE_DIR / "partials" / "_lineage.html.j2").read_text(encoding="utf-8")
    assert "value--run-id" in template_src
    assert 'style="font-size: 12px; font-family: var(--font-mono);">{{ lineage.run_id }}' not in template_src


# ---- Phase P7 (cover page brand-text bleed) --------------------------------------------------


def test_render_pdf_cover_page_has_no_recurring_brand_footer_text(tmp_path):
    # Regression guard for the bug this phase fixes: the recurring @bottom-left/@top-right
    # "BeeSINT — beesint.com" margin-box text used to bleed onto the cover page (page 0) because
    # `@page :first` couldn't override the base `@page` rule's margin-box `content` on WeasyPrint
    # 62.3 (confirmed empirically — `content: none` and `content: "";` both still leaked). Fixed
    # via a named page (`page: cover` on `.cover` + `@page cover { ... }`), a fully separate page
    # context rather than a cascade override attempt.
    output_path = tmp_path / "report.pdf"
    render_pdf(minimal_context(), output_path)

    reader = PdfReader(str(output_path))
    cover_text = reader.pages[0].extract_text() or ""
    assert "beesint.com" not in cover_text.lower()


def test_report_css_cover_uses_named_page_not_first_pseudo_class():
    css = _REPORT_CSS_PATH.read_text(encoding="utf-8")
    assert "page: cover;" in css
    assert "@page cover {" in css
    assert "@page :first {" not in css


# ---- Phase P8 (border-radius: cards get sharp corners) ---------------------------------------


def test_report_css_card_radius_tokens_are_zero():
    # Cards (.kpi-card/.chart-card/.map-frame all use --radius-md) get sharp corners — explicit
    # DA request. --radius-full stays a pill (chips are tags, not cards).
    css = _REPORT_CSS_PATH.read_text(encoding="utf-8")
    root_block = css.split(":root {", 1)[1].split("}", 1)[0]
    assert "--radius-md: 0px;" in root_block
    assert "--radius-lg: 0px;" in root_block
    assert "--radius-full: 9999px;" in root_block


# ---- Phase P2 (TOC paginé + restructuration Executive Summary) -------------------------------

_SEC_IDS = [
    "sec-executive-summary",
    "sec-sources-status",
    "sec-cve-critical",
    "sec-kev",
    "sec-mttk",
    "sec-c2-infra",
    "sec-malicious-urls",
    "sec-breaches",
    "sec-top-countries",
    "sec-top-vendors",
    "sec-cwe-breakdown",
    "sec-lineage",
]


def test_report_css_toc_uses_target_counter_for_real_page_numbers():
    css = _REPORT_CSS_PATH.read_text(encoding="utf-8")
    assert "target-counter(attr(href), page)" in css


def test_summary_template_is_pure_toc_kpi_and_chart_moved_out():
    # Garde-fou : le contenu déplacé vers _executive_summary.html.j2 ne doit pas être dupliqué ici.
    template_src = (_TEMPLATE_DIR / "partials" / "_summary.html.j2").read_text(encoding="utf-8")
    assert "toc-list" in template_src
    assert "kpi-grid" not in template_src
    assert "chart-row" not in template_src


def test_executive_summary_template_has_kpi_grid_and_chart_card_full():
    template_src = (_TEMPLATE_DIR / "partials" / "_executive_summary.html.j2").read_text(encoding="utf-8")
    assert "kpi-grid" in template_src
    assert "chart-card--full" in template_src
    assert "flex-basis: 100%" not in template_src


def test_render_pdf_toc_shows_real_page_numbers(tmp_path):
    output_path = tmp_path / "report.pdf"
    render_pdf(minimal_context(), output_path)

    reader = PdfReader(str(output_path))
    # La page "Contents" n'a plus un index fixe (1f a inséré une page Executive Deep-Dive avant
    # elle, la décalant de la page 2 à la page 3 sur ce fixture minimal) — chercher la page par
    # son propre titre plutôt que de figer un index, plus robuste à un futur ajout de section
    # avant la TOC. Chaque page number référencé doit rester une vraie référence de page (jamais
    # "0"/absent, ce qui indiquerait un échec silencieux de target-counter sur cette version de
    # WeasyPrint).
    contents_text = next(
        (page.extract_text() or "" for page in reader.pages if "Contents" in (page.extract_text() or "")), ""
    )
    assert contents_text, "no page found containing the Contents/TOC section"
    assert "New critical CVEs" in contents_text


def test_all_toc_target_ids_present_in_rendered_html():
    # Chaque href="#sec-x" du sommaire doit correspondre à un id="sec-x" réellement présent
    # ailleurs dans le document — sinon target-counter ne peut rien résoudre (page vide/absente).
    html = _render_html(minimal_context())
    for sec_id in _SEC_IDS:
        assert f'id="{sec_id}"' in html, f"missing anchor id={sec_id!r} referenced by the TOC"


# ---- Phase P3 (nouvelle métrique MTTK : CISA remediation window) ------------------------------


def test_mttk_template_has_sec_id_anchor():
    template_src = (_TEMPLATE_DIR / "partials" / "_mttk.html.j2").read_text(encoding="utf-8")
    assert 'id="sec-mttk"' in template_src


def test_mttk_template_renders_remediation_tile_unconditionally():
    # La tuile remediation_window_days doit apparaître que sample_size soit > 0 ou == 0
    # (contrairement aux 3 tuiles average/median/sample et à la jauge, restées conditionnelles) —
    # c'est tout l'intérêt de cette métrique "toujours peuplée" à côté du gauge honnête. 1n l'a
    # déplacée dans le même .kpi-grid que les 3 autres, mais hors du bloc conditionnel
    # `{% if mttk.sample_size > 0 %}`.
    template_src = (_TEMPLATE_DIR / "partials" / "_mttk.html.j2").read_text(encoding="utf-8")
    assert "CISA remediation window" in template_src
    conditional_block = template_src.split("{% if mttk.sample_size > 0 %}", 1)[1].split("{% endif %}", 1)[0]
    assert "remediation_window_days" not in conditional_block


def test_render_pdf_mttk_remediation_card_shows_even_with_zero_sample_size(tmp_path):
    context = minimal_context()
    context["mttk"]["sample_size"] = 0
    context["mttk"]["average_days"] = None
    context["mttk"]["median_days"] = None
    context["mttk"]["gauge_svg"] = None
    context["mttk"]["remediation_window_days"] = 9.5

    output_path = tmp_path / "report.pdf"
    render_pdf(context, output_path)

    reader = PdfReader(str(output_path))
    # .kpi-card .label est en text-transform:uppercase (CSS), même raison que
    # test_render_pdf_all_section_titles_present pour la casse comparée en upper().
    full_text_upper = "\n".join(page.extract_text() or "" for page in reader.pages).upper()
    assert "9.5" in full_text_upper
    assert "CISA REMEDIATION WINDOW" in full_text_upper


def test_report_css_mttk_kpi_grid_card_has_no_orphaned_classes():
    # 1n : le layout MTTK 4-tuiles réutilise .chart-card + .kpi-grid tel quel (déjà couverts par
    # test_report_css_kpi_grid_compensates_last_card_margin/test_report_css_chart_card_full_
    # matches_chart_card_right_margin pour la compensation de marge) — plus de classe CSS dédiée
    # MTTK à tester séparément, juste une regression guard sur leur suppression complète.
    css = _REPORT_CSS_PATH.read_text(encoding="utf-8")
    assert ".mttk-kpi-column" not in css
    assert ".mttk-remediation-card" not in css


# ---- Phase P5 (nouvelle section "Breaches This Week") -----------------------------------------


def test_breaches_template_has_sec_id_anchor():
    template_src = (_TEMPLATE_DIR / "partials" / "_breaches.html.j2").read_text(encoding="utf-8")
    assert 'id="sec-breaches"' in template_src


def test_summary_template_toc_has_breaches_entry():
    # Second passage assumé sur _summary.html.j2 (cf. CDC Phase P5) — 10e entrée TOC ajoutée une
    # fois la section existante, la seule exception documentée à "un seul passage par fichier".
    template_src = (_TEMPLATE_DIR / "partials" / "_summary.html.j2").read_text(encoding="utf-8")
    assert 'href="#sec-breaches"' in template_src
    assert "Breaches this week" in template_src


def test_report_html_includes_breaches_right_after_malicious_urls():
    template_src = (_TEMPLATE_DIR / "report.html.j2").read_text(encoding="utf-8")
    malicious_urls_pos = template_src.index('partials/_malicious_urls.html.j2"')
    breaches_pos = template_src.index('partials/_breaches.html.j2"')
    assert malicious_urls_pos < breaches_pos


def test_report_html_top_countries_follows_c2_infra_not_breaches():
    # top_countries.html.j2 se réfère explicitement aux "active C2 servers above" — doit suivre
    # directement _c2_infra, pas être relégué après Breaches/ThreatFox/Malicious URLs comme avant.
    template_src = (_TEMPLATE_DIR / "report.html.j2").read_text(encoding="utf-8")
    c2_pos = template_src.index('partials/_c2_infra.html.j2"')
    top_countries_pos = template_src.index('partials/_top_countries.html.j2"')
    threatfox_pos = template_src.index('partials/_threatfox.html.j2"')
    assert c2_pos < top_countries_pos < threatfox_pos


def test_report_html_top_vendors_follows_cve_critical():
    # top_vendors.html.j2 agrège les vendors des CVE critiques de la semaine — doit suivre
    # _cve_critical, pas rester coincé après Breaches (aucun rapport avec les C2/breaches).
    template_src = (_TEMPLATE_DIR / "report.html.j2").read_text(encoding="utf-8")
    cve_pos = template_src.index('partials/_cve_critical.html.j2"')
    top_vendors_pos = template_src.index('partials/_top_vendors.html.j2"')
    kev_pos = template_src.index('partials/_kev.html.j2"')
    assert cve_pos < top_vendors_pos < kev_pos


def test_render_pdf_breaches_section_shows_spotlight_donut_and_bar_chart(tmp_path):
    context = minimal_context()
    context["breaches"]["severity_donut"] = (
        '<svg viewBox="0 0 10 10" class="severity-donut"><circle cx="5" cy="5" r="2"/></svg>'
    )
    context["breaches"]["impact_chart"] = '<svg viewBox="0 0 10 10" class="mini-bar-chart"></svg>'

    output_path = tmp_path / "report.pdf"
    render_pdf(context, output_path)

    reader = PdfReader(str(output_path))
    full_text = "\n".join(page.extract_text() or "" for page in reader.pages)
    full_text_upper = full_text.upper()
    assert "BREACHES THIS WEEK" in full_text_upper
    assert "ExampleCorp" in full_text
    assert "1.2M" in full_text
    assert "Also cross-checked in BreachDirectory" in full_text


def test_render_pdf_breaches_section_degrades_gracefully_with_no_new_breaches(tmp_path):
    # RAPIDAPI_KEY absente / aucune nouvelle breach ce run -> la section ne doit jamais faire
    # planter le rendu (cf. CDC "never block the pipeline").
    context = minimal_context()
    context["breaches"] = {
        "new_count": 0,
        "total_accounts_exposed": "0",
        "spotlight": None,
        "severity_breakdown": [],
        "severity_donut": None,
        "impact_chart": None,
    }

    output_path = tmp_path / "report.pdf"
    render_pdf(context, output_path)
    assert output_path.exists()
