from __future__ import annotations
import os
from jinja2 import Environment, FileSystemLoader

_env = Environment(loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), "templates")))

TITLES = {
    "executive": "Executive Vulnerability Assessment Report",
    "technical": "Technical Vulnerability Assessment Report",
    "compliance": "Compliance Vulnerability Assessment Report",
}


def generate_html_report(data: dict) -> str:
    template = _env.get_template("report.html")
    return template.render(
        data=data,
        report_type=data["report_type"],
        report_title=TITLES.get(data["report_type"], "Vulnerability Assessment Report"),
    )
