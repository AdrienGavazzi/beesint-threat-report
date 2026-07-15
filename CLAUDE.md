# CLAUDE.md

Guidance for Claude Code working in `beesint-threat-report` — the weekly cyber threat intel ETL pipeline. Separate repo from `beesint-backend`/`beesint-frontend`/`beesint-jobs`; see root `CLAUDE.md`'s "Threat Report Pipeline" section for how it fits into the rest of BeeSINT.

---

## Architecture

Cron-driven (GitHub Actions, see `.github/workflows/cron-etl.yml`), no server process. Entry point: `orchestrate.py::run()`.

Layers, in order:
1. **`extract/`** — one module per source (`nvd.py`, `kev.py`, `feodo.py`, `urlhaus.py`, `threatfox.py`), each an async `httpx` call returning a raw `polars` DataFrame. Every extractor degrades independently: a failed source returns an empty frame + a `sources_status["<name>"] = "failed"` entry, the run continues rather than aborting (never let one dead API kill the whole report).
2. **`transform/`** — `dedup.py`, `diffing.py` (new-vs-seen-before), `geoloc.py` (ip-api.com batch), `kpis.py` (`ReportKpis`), `mttk.py` (mean-time-to-KEV), `ranking.py` (`rank_top_n_cves`/`rank_top_n_ips`/`rank_top_n_urls` — every list in the report is top-N bounded here, keeps PDF size/page-count sane).
3. **`validate/`** — `schemas.py` (Pydantic row models), `frames.py` (pandera frame-level schemas).
4. **`load/`** — `pdf_context.py` (the single place raw data becomes template-ready dicts: chart SVGs, chip-list aggregations, date formatting, lineage), `pdf_renderer.py` (Jinja env + WeasyPrint call), `json_writer.py` (public JSON API payload — shares the same item-level dicts as the PDF context, so a data fix in `orchestrate.py`'s `_build_top_cves`/`_build_top_ips` affects both surfaces at once).

Output: PDF (WeasyPrint) + JSON (public API) + entry appended to S3 `runs/index.json`, then a webhook POST to the backend (`publish/webhook.py`) unless `dry_run` (no `BACKEND_WEBHOOK_URL` configured).

---

## Data source integration rule

New sources must **enrich an existing tracked entity**, never become their own isolated report section. A source describing a C2 IP (Shodan InternetDB, Spamhaus DROP/EDROP, GreyNoise) merges into the existing `c2_items` record for that IP. A source describing a malicious URL (PhishTank) merges into `malicious_url_items` by normalized URL, deduped against URLhaus — never list the same URL twice because two feeds reported it. The payoff of merging is a cross-source signal ("confirmed by N feeds") that's more useful than either source shown alone.

The merge step runs **before** `transform/ranking.py`'s top-N cut, and cross-confirmed entries should sort ahead of single-source ones within that cut.

Any new technical field (open ports, CIDR cross-confirmation, IP classification) should get its headline finding echoed as a plain-language sentence in `pdf_context.py::_build_executive_summary()` — see "Target audience" below.

---

## Target audience

`_build_executive_summary()`'s docstring states it explicitly: the report's primary reader is a **non-expert-cyber recruiter** — plain language, no jargon, no "vs last week" comparison on a cold start. The report intentionally also carries technical depth further down (raw CVE IDs, CVSS scores, ASN numbers, tables) for credibility with a technical reviewer — that split is deliberate. When adding new data, the technical detail can live in tables/badges, but the *headline* finding belongs in the executive summary too, or it only reaches the technical fraction of readers.

---

## WeasyPrint 62.3 — empirically verified limits

Pinned in `requirements.txt` (`weasyprint==62.3` — don't bump without re-verifying these, `pydyf>=0.12` is known to break the `Stream.transform` API this version relies on). All of the following are documented inline in `styles/report.css` — treat as proven, don't re-test:

- No CSS Grid `repeat(auto-fit, ...)` — silently ignored with a render warning. Use `display: flex; flex-wrap: wrap; gap` instead (already the pattern for `.kpi-grid`, `.chart-row`).
- Nested `flex + gap` inside a `flex-wrap` parent breaks text wrapping for short adjacent tokens (verified on badges). Use `display: inline-block` + `margin` instead for anything wrapping short text (`.chip`, `.source-badge`).
- `<th>`, `<strong>`, `.section-title` need an explicit `font-weight` reset. The UA-stylesheet default bold (700) isn't in any embedded webfont (Syne/Plus Jakarta Sans/JetBrains Mono ship 400/500/600 only) — an unset weight silently falls back to a forbidden system font.
- `@page` margin boxes (`@bottom-left`/`@bottom-center`/`@bottom-right`, `@page :first`) are WeasyPrint/CSS-Paged-Media syntax, not standard browser CSS — don't expect them to behave like anything testable in a normal browser devtools.
- The `@page` background must be set on `@page` itself, not just `body` — `body { background }` only covers the content box, not the margin area (confirmed by the explicit fallback-to-white-frame bug this codebase already hit once).
- No live network calls during PDF render — the world map is a bundled static asset, not a live tile fetch. Deliberate reliability principle: an ETL run must never depend on a third-party tile service being up just to draw a chart. Any new chart-building code in `pdf_context.py` must stay offline too.
- Charts render nothing (`None`) below a real-signal threshold rather than showing a meaningless chart — see `_HISTOGRAM_MIN_ITEMS`, `_build_severity_donut_svg`'s `total > 0` check, and the chip-list-over-bar-chart choice for top countries/vendors (most real counts were 1, a bar chart of all-1s communicates nothing a number doesn't already say). New charts must follow the same discipline.

---

## Testing

`pytest` — `tests/test_load_pdf_renderer.py` asserts on rendered CSS/HTML behavior directly (skipped if Pango/GTK isn't available, e.g. plain Windows without the WeasyPrint system deps). Extend this file rather than adding a parallel one when testing new template/CSS behavior.
