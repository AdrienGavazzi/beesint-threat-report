from __future__ import annotations

from pathlib import Path

import jinja2

_TEMPLATE_DIR = Path(__file__).resolve().parents[3] / "templates"


def render_pdf(context: dict, output_path: Path) -> Path:
    # import différé : weasyprint charge Pango/GTK au niveau module (absent nativement sur
    # Windows, cf. CDC §24) — un import top-level ferait échouer tout l'arbre d'imports
    # (orchestrate.py, tests) même quand le PDF n'est jamais rendu.
    import weasyprint

    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(_TEMPLATE_DIR)),
        undefined=jinja2.StrictUndefined,
    )
    template = env.get_template("report.html.j2")
    html = template.render(**context)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    # base_url = dossier templates/ : les chemins relatifs du CSS (../styles/report.css)
    # et des @font-face (fonts/*.woff2) se résolvent depuis là, peu importe le cwd du process
    # (cron GitHub Actions vs run local, cf. lot 5 §"Fonction de rendu").
    weasyprint.HTML(string=html, base_url=str(_TEMPLATE_DIR)).write_pdf(str(output_path))
    return output_path
