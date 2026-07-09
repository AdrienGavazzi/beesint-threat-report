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


def test_render_pdf_minimal_context_produces_valid_pdf(tmp_path):
    context = {
        "run_id": "run-1",
        "status": "success",
        "period_start": "2026-06-01",
        "period_end": "2026-06-08",
        "generated_at": "2026-06-08T00:00:00Z",
        "kpis": {
            "cve_critical_count": 2,
            "cve_high_count": 5,
            "kev_new_count": 1,
            "mean_time_to_kev_days": 4.5,
            "c2_active_count": 1,
            "malicious_url_count": 2,
        },
        "top_countries": [{"country": "US", "count": 3}],
        "top_cves": [{"cve_id": "CVE-2026-1", "cvss_score": 9.8, "vendor": "acme"}],
    }
    output_path = tmp_path / "report.pdf"

    result = render_pdf(context, output_path)

    assert result == output_path
    assert output_path.exists()
    reader = PdfReader(str(output_path))
    assert len(reader.pages) >= 1
