import copy

import jinja2
import pytest
from pypdf import PdfReader

from beesint_threat_report.load.pdf_renderer import render_pdf

try:
    import weasyprint  # noqa: F401

    _WEASYPRINT_AVAILABLE = True
except OSError:
    # Pango/GTK absent (Windows sans MSYS2, cf. CDC §24) — skip plutôt que crash de collecte.
    _WEASYPRINT_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not _WEASYPRINT_AVAILABLE, reason="Pango/GTK indisponible (WeasyPrint ne peut pas charger)"
)

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
        "mttk": {"average_days": 4.5, "median_days": 3.0, "sample_size": 1},
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
                }
            ],
            "sparkline": None,
            "map_svg": None,
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
                }
            ],
            "sparkline": None,
        },
        "threatfox": {"enabled": False, "families_count": 0, "families_trend_pct": None},
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
            "sources": [
                {"name": "NVD", "url": "https://nvd.nist.gov/", "note": "Domaine public."},
                {
                    "name": "abuse.ch FeodoTracker",
                    "url": "https://feodotracker.abuse.ch/",
                    "note": "Data kindly provided by abuse.ch",
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


def test_render_pdf_abuse_ch_attribution_on_every_page(tmp_path):
    output_path = tmp_path / "report.pdf"
    render_pdf(minimal_context(), output_path)

    reader = PdfReader(str(output_path))
    assert len(reader.pages) >= 1
    for index, page in enumerate(reader.pages):
        text = page.extract_text() or ""
        assert "Data kindly provided by abuse.ch" in text, f"missing abuse.ch attribution on page {index}"


def test_render_pdf_creates_missing_output_directory(tmp_path):
    output_path = tmp_path / "nested" / "dir" / "report.pdf"

    render_pdf(minimal_context(), output_path)

    assert output_path.exists()


def test_render_pdf_does_not_mutate_input_context(tmp_path):
    context = minimal_context()
    snapshot = copy.deepcopy(context)

    render_pdf(context, tmp_path / "report.pdf")

    assert context == snapshot
