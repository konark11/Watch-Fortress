"""
PDF report generator using reportlab's Platypus flowables directly (not an
HTML-to-PDF conversion). This is a deliberate choice: weasyprint/wkhtmltopdf
need system-level Cairo/Pango/Qt libraries that may not be present on an
air-gapped box and are painful to install without internet access.
reportlab is pure Python with no system dependencies beyond what pip
already installed, which matters for a platform that has to run in
locked-down and offline environments.
"""
from __future__ import annotations
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

SEVERITY_COLORS = {
    "critical": colors.HexColor("#d92d3f"), "high": colors.HexColor("#e8792f"),
    "medium": colors.HexColor("#e0b127"), "low": colors.HexColor("#4f9ecf"), "info": colors.HexColor("#999999"),
}

TITLES = {
    "executive": "Executive Vulnerability Assessment Report",
    "technical": "Technical Vulnerability Assessment Report",
    "compliance": "Compliance Vulnerability Assessment Report",
}


def generate_pdf_report(data: dict, output_path: str):
    doc = SimpleDocTemplate(output_path, pagesize=letter, topMargin=0.6 * inch, bottomMargin=0.6 * inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleBlue", parent=styles["Title"], textColor=colors.HexColor("#1a4d8f"))
    h2_style = ParagraphStyle("H2Blue", parent=styles["Heading2"], textColor=colors.HexColor("#1a4d8f"), spaceBefore=14)
    body = styles["BodyText"]
    small = ParagraphStyle("Small", parent=styles["BodyText"], fontSize=8.5, textColor=colors.grey)

    story = []
    report_type = data["report_type"]
    story.append(Paragraph(TITLES.get(report_type, "Vulnerability Assessment Report"), title_style))
    story.append(Paragraph(f"Generated {data['generated_at']} &middot; Scope: {data['scope']}", small))
    story.append(Spacer(1, 14))

    kpi_data = [
        ["Assets", "Vulnerabilities", "Critical", "Known Exploited", "Exploit Available"],
        [str(data["summary"]["total_assets"]), str(data["summary"]["total_vulnerabilities"]),
         str(data["summary"]["severity_counts"]["critical"]), str(data["summary"]["kev_count"]),
         str(data["summary"]["exploitable_count"])],
    ]
    kpi_table = Table(kpi_data, colWidths=[1.9 * inch] * 5)
    kpi_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a4d8f")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e0e4eb")),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#f4f6fa")),
        ("FONTSIZE", (0, 1), (-1, 1), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 16))

    if report_type == "executive":
        story.append(Paragraph("Executive Summary", h2_style))
        s = data["summary"]
        summary_text = (
            f"This assessment identified {s['total_vulnerabilities']} vulnerabilities across "
            f"{s['total_assets']} assets, including {s['severity_counts']['critical']} critical and "
            f"{s['severity_counts']['high']} high severity findings. "
        )
        if s["kev_count"] > 0:
            summary_text += (
                f"{s['kev_count']} of these are listed in the CISA Known Exploited Vulnerabilities "
                f"catalog and represent active, real-world attacker interest; remediation should be "
                f"prioritized accordingly."
            )
        story.append(Paragraph(summary_text, body))
        story.append(Spacer(1, 10))

        story.append(Paragraph("Top Risk Findings", h2_style))
        rows = [["Finding", "Severity", "Asset", "Risk"]]
        for f in data["top_risk_findings"]:
            rows.append([f["title"][:55], f["severity"].upper(), f["asset_ip"], str(f["risk_score"])])
        story.append(_styled_table(rows, [3.2 * inch, 1 * inch, 1.4 * inch, 0.8 * inch]))
        story.append(Spacer(1, 10))

        story.append(Paragraph("Most At-Risk Assets", h2_style))
        rows = [["IP Address", "Hostname", "Criticality", "Max Risk"]]
        for a in data["critical_assets"]:
            rows.append([a["ip"], a.get("hostname") or "-", a["criticality"], str(a["max_risk_score"])])
        story.append(_styled_table(rows, [1.6 * inch, 2 * inch, 1.4 * inch, 1.2 * inch]))

    elif report_type == "technical":
        story.append(Paragraph(f"Detailed Findings ({len(data['findings'])})", h2_style))
        for f in data["findings"]:
            story.append(Spacer(1, 8))
            header = f"<b>{f['title']}</b> &mdash; <font color='{SEVERITY_COLORS.get(f['severity'], colors.grey).hexval()}'><b>{f['severity'].upper()}</b></font>"
            story.append(Paragraph(header, body))
            meta = f"{f['asset_ip']}{' (' + f['asset_hostname'] + ')' if f['asset_hostname'] else ''}{':' + str(f['port']) if f['port'] else ''} &middot; CVSS {f['cvss_score'] or 'n/a'} &middot; Risk {f['risk_score']} ({f['risk_band']})"
            story.append(Paragraph(meta, small))
            story.append(Paragraph(f["description"] or "No description available.", body))
            tags = ", ".join(f["cve_ids"] + f["cwe_ids"] + f["attack_techniques"] + f["owasp_categories"])
            if f["kev_listed"]:
                tags += " | CISA KEV"
            if f["exploit_available"]:
                tags += " | Exploit Available"
            if tags:
                story.append(Paragraph(f"<i>{tags}</i>", small))
            story.append(Paragraph(f"<b>Remediation:</b> {f['remediation']}", body))
            story.append(Paragraph(f"Detected by: {', '.join(f['source_scanners'])}", small))

    elif report_type == "compliance":
        story.append(Paragraph(f"Compliance Mapping &mdash; {data.get('compliance_framework', '')}", h2_style))
        rows = [["Finding", "Severity", "Asset", "Mapped Controls"]]
        for r in data.get("compliance_rows", []):
            rows.append([r["finding"][:40], r["severity"].upper(), r["asset_ip"], "; ".join(r["controls"])[:80]])
        story.append(_styled_table(rows, [2.2 * inch, 0.9 * inch, 1.3 * inch, 2.1 * inch]))

    doc.build(story)


def _styled_table(rows, col_widths):
    t = Table(rows, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a4d8f")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e0e4eb")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafc")]),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return t
