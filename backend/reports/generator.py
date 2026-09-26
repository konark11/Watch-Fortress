from __future__ import annotations
import os
import json
import uuid
from sqlalchemy.orm import Session

from models.database import ReportJob, ReportType, ReportFormat
from reports.data_builder import build_report_data
from reports.html_report import generate_html_report
from reports.pdf_report import generate_pdf_report
from reports.docx_report import generate_docx_report

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "reports")
os.makedirs(OUTPUT_DIR, exist_ok=True)


def generate_report(
    db: Session,
    report_type: str,
    report_format: str,
    scope_asset_ids: list[int] | None = None,
    compliance_framework: str | None = None,
    generated_by: str = "system",
) -> ReportJob:
    data = build_report_data(db, report_type, scope_asset_ids, compliance_framework)

    file_id = uuid.uuid4().hex[:10]
    filename = f"{report_type}_report_{file_id}.{report_format}"
    output_path = os.path.join(OUTPUT_DIR, filename)

    if report_format == "html":
        html = generate_html_report(data)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
    elif report_format == "pdf":
        generate_pdf_report(data, output_path)
    elif report_format == "docx":
        generate_docx_report(data, output_path)
    elif report_format == "json":
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
    else:
        raise ValueError(f"Unsupported report format: {report_format}")

    job = ReportJob(
        report_type=ReportType(report_type),
        report_format=ReportFormat(report_format),
        scope_description=data["scope"],
        generated_by=generated_by,
        file_path=output_path,
        compliance_framework=compliance_framework,
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job
