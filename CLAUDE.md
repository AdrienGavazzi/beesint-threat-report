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

New sources must **enrich an existing tracked entity**, never become their own isolated report section. A source describing a C2 IP (Shodan InternetDB, Spamhaus DROP/EDROP, GreyNoise) merges into the existing `c2_items` record for that IP. A source describing a malicious URL (OpenPhish) merges into `malicious_url_items` by normalized URL, deduped against URLhaus — never list the same URL twice because two feeds reported it. The payoff of merging is a cross-source signal ("confirmed by N feeds") that's more useful than either source shown alone.

**PhishTank → OpenPhish:** PhishTank was removed (`extract/phishtank.py`, `transform/phishtank_merge.py`) because its signups are closed — no API key is obtainable anymore, so the source could never activate. Replaced by OpenPhish (`extract/openphish.py`, `transform/openphish_merge.py`): a free public feed (`feed.txt`, one URL per line), no API key, no hard rate limit. Same merge role, same theme (malicious URLs), just a different upstream. If PhishTank ever becomes viable again, don't resurrect the old files — OpenPhish already fills this role cleanly.

The merge step runs **before** `transform/ranking.py`'s top-N cut, and cross-confirmed entries should sort ahead of single-source ones within that cut.

Any new technical field (open ports, CIDR cross-confirmation, IP classification) should get its headline finding echoed as a plain-language sentence in `pdf_context.py::_build_executive_summary()` — see "Target audience" below.

---

## Target audience

`_build_executive_summary()`'s docstring says "non-expert-cyber recruiter" — that governs only the executive-summary paragraph's *tone* (plain language, no jargon, no "vs last week" on a cold start). Per the actual CDC (`beesint-infra/docs/threat-report.md` §1-2), this component is a **Data Engineer/Cyber portfolio piece** — but the portfolio narrative belongs in the ETL repo's own README (§25), never in the report's own content (confirmed decision: no pipeline-architecture diagram or tech-stack chip strip inside the report itself). The report stays purely technical/functional; the one place worth extra care because a technical reviewer reads it closely is the Pipeline Lineage/Attribution section (run reproducibility, source attribution) — not because it should self-promote, but because it's the section most likely to be scrutinized as engineering work.

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
- **`flex-wrap` + `gap` silently drops the gap once wrapping actually forces multiple lines** (confirmed empirically via a real render, not just CSS reading — distinct from the nested-flex-text-wrap issue above). `.kpi-grid`/`.chart-row` use `flex+gap` safely only because they never have enough cards to wrap past 1 row. `.lineage-grid` had 7 cards wrapping to 3 rows and rendered with literally zero gap (borders touching) until fixed by giving `.lineage-card` an explicit `margin` instead of relying on the parent's `gap` — this class was later removed entirely in the Phase B lineage redesign (sober grouped list, `.lineage-list`/`.lineage-row`, no more card look), but the underlying `flex-wrap`+`gap` finding still stands for any future grid. Any new grid that might wrap to 2+ rows should use the margin pattern from the start, not `gap`.
- **A `flex` item with a fixed `flex: 0 0 Npx` basis and text wider than that basis does not wrap/clip to the basis the way a browser would — it overflows to its natural content width, which visually "eats" the parent's `gap` even on a plain `nowrap` flex row (no wrapping involved at all).** Confirmed empirically on `.lineage-row` (Phase B): 3 fixed/auto-basis children (`flex: 0 0 200px` name, `flex: 1 1 auto` url, `flex: 0 0 200px` note) with `gap: 10px` rendered with the 3 columns flush against each other, zero visible gap, whenever the name text exceeded 200px — distinct from both `flex-wrap`+`gap` (above) and the nested-flex-text-wrap issue, since this row never wraps at all. Fix: drop `gap` in favor of explicit `margin-right` on the fixed-basis children (same margin-over-gap principle as the wrap case), plus `white-space: nowrap; overflow: hidden; text-overflow: ellipsis` on those children so overflow truncates instead of visually devouring the neighboring column's spacing.
- **`content: url(image.png) " text"` inside an `@bottom-left`/`@bottom-right`/`@bottom-center` margin box renders the image, but at its native pixel resolution with no way to constrain it** — a margin box doesn't support a nested selector to style the generated "content" node (no `@bottom-left img { width: ... }` equivalent in CSS Paged Media), and `width`/`height` set on the margin box itself has no effect on the image it generates. Confirmed empirically: a 150×146px logo rendered at that native size inside a ~2.6cm-tall footer margin box completely covered the page. No known workaround on WeasyPrint 62.3 — fall back to text-only footer content when a logo is wanted there (`report.css` `@bottom-left` uses `"BeeSINT — beesint.com"` text for this reason, not the logo asset used elsewhere in the report).
- **SVG root elements with explicit `width`/`height` attributes ignore a CSS rule trying to override them to `100%`** (this was already known for `.map-frame svg`; confirmed to also apply to any other full-width chart card). `_build_history_line_chart_svg`/`_build_area_chart_svg` (`pdf_context.py`) used to set `width="{width}" height="{height}"` pixel attributes on the `<svg>` root — even with a `.chart-card svg.history-line-chart { width: 100% }` CSS rule in place, the chart rendered at its fixed intrinsic pixel width (visibly stopping partway across a full-width card) rather than stretching. Fix is the same as the map: drop the `width`/`height` attributes from the `<svg>` root entirely (keep only `viewBox`), and let the CSS rule do the sizing.

---

## Testing

`pytest` — `tests/test_load_pdf_renderer.py` asserts on rendered CSS/HTML behavior directly (skipped if Pango/GTK isn't available, e.g. plain Windows without the WeasyPrint system deps). Extend this file rather than adding a parallel one when testing new template/CSS behavior.
