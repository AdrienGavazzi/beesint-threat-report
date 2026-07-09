from __future__ import annotations

from pathlib import Path

import jinja2

_TEMPLATE_DIR = Path(__file__).resolve().parents[3] / "templates"


def render_pdf(context: dict, output_path: Path) -> Path:
    # import différé : weasyprint charge Pango/GTK au niveau module (absent nativement sur
    # Windows, cf. CDC §24) — un import top-level ferait échouer tout l'arbre d'imports
    # (orchestrate.py, tests) même quand le PDF n'est jamais rendu.
    import weasyprint

    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(_TEMPLATE_DIR)))
    template = env.get_template("report.html.j2")
    html = template.render(**context)
    weasyprint.HTML(string=html).write_pdf(str(output_path))
    return output_path
