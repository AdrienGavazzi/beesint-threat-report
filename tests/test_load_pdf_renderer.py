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
    "Source Status",
    "Contents",
    "New Critical CVEs",
    "CISA KEV Additions",
    "Mean-Time-to-KEV",
    "Active C2 Infrastructure",
    "Malicious URLs Online",
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
                "kev_new_count": 1,
                "c2_active_count": 1,
                "malicious_url_count": 2,
            },
        },
        "executive_summary": "This week, the pipeline tracked 2 new critical CVEs. "
        "1 was added to CISA's Known Exploited Vulnerabilities catalog, including at least "
        "one tied to known ransomware activity. 1 command-and-control server(s) remain "
        "active and 2 malicious URLs were seen online in the monitored feeds.",
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
                }
            ],
            "sparkline": None,
            "severity_donut": None,
            "cvss_histogram": None,
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
                }
            ],
            "urgency_flag": True,
            "sparkline": None,
        },
        "mttk": {"average_days": 4.5, "median_days": 3.0, "sample_size": 1, "gauge_svg": None},
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
                }
            ],
            "sparkline": None,
            # SVG minimal non-None : exerce le nouveau bloc légende de carte (couleurs par rang,
            # cf. CDC Phase B point 8) dans test_render_pdf_c2_map_legend_matches_table_colors.
            "map_svg": '<svg viewBox="0 0 10 10" class="world-map"><circle cx="5" cy="5" r="2"/></svg>',
            "malware_family_breakdown": [
                {"malware_family": "Heodo", "count": 1, "pct_of_total": 100.0, "color": "#0EA5E9"}
            ],
            "malware_family_chart": None,
            "top_asn": [{"asn": "AS64500 EXAMPLE-AS", "count": 1, "pct_of_total": 100.0, "color": "#0EA5E9"}],
            "top_asn_chart": None,
            "open_ports_breakdown": [{"port": 443, "count": 1, "pct_of_total": 100.0, "color": "#0EA5E9"}],
            "open_ports_chart": None,
            "cross_confirmed": {"confirmed": 1, "total": 1},
            # Mappings nom -> couleur consommés par le tableau (cellules Malware family/ASN),
            # même valeur que malware_family_breakdown/top_asn[0]["color"] ci-dessus.
            "malware_color_by_name": {"Heodo": "#0EA5E9"},
            "asn_color_by_name": {"AS64500 EXAMPLE-AS": "#0EA5E9"},
        },
        "malicious_urls": {
            "online_count": 2,
            "trend_pct": None,
            "items": [
                {
                    "url": "http://malicious.example.com/payload",
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
        "threatfox": {"enabled": False, "families_count": 0, "families_trend_pct": None, "sparkline": None},
        "geo": {
            "top_countries": [
                {"country_name": "United States", "country_code": "US", "count": 3, "pct_of_total": 60.0},
                {"country_name": "Germany", "country_code": "DE", "count": 2, "pct_of_total": 40.0},
            ]
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


def test_mttk_template_uses_kpi_column_not_wrapper_card():
    # Point 7 : les 3 KPI MTTK ne doivent plus être encadrés par une card .chart-card superflue —
    # ils vivent directement dans .mttk-kpi-column (colonne verticale à droite de la jauge).
    template_src = (_TEMPLATE_DIR / "partials" / "_mttk.html.j2").read_text(encoding="utf-8")
    assert "mttk-kpi-column" in template_src
    assert 'class="kpi-grid"' not in template_src


def test_lineage_template_has_no_card_look():
    # Point 10 : la section lineage ne doit plus utiliser .lineage-grid/.lineage-card (look card) —
    # remplacée par une liste sobre groupée par catégorie.
    template_src = (_TEMPLATE_DIR / "partials" / "_lineage.html.j2").read_text(encoding="utf-8")
    assert "lineage-grid" not in template_src
    assert "lineage-card" not in template_src
    assert "lineage-list" in template_src


def test_render_html_c2_table_and_map_legend_share_rank_colors():
    # Point 8 : la couleur de la cellule "Malware family"/"ASN" en table doit matcher la couleur
    # du point sur la carte / de l'entrée de légende, via le même mapping malware_color_by_name
    # (couleur inline non observable via extraction de texte PDF — assertion sur le HTML brut).
    html = _render_html(minimal_context())
    assert 'style="color: #0EA5E9;"' in html
    assert "background:#0EA5E9" in html  # dot de légende sous la carte (.map-legend)


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
