from __future__ import annotations
from docx import Document
from docx.shared import Pt, RGBColor, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH

TITLES = {
    "executive": "Executive Vulnerability Assessment Report",
    "technical": "Technical Vulnerability Assessment Report",
    "compliance": "Compliance Vulnerability Assessment Report",
}

BRAND_BLUE = RGBColor(0x1A, 0x4D, 0x8F)
SEVERITY_COLORS = {
    "critical": RGBColor(0xD9, 0x2D, 0x3F), "high": RGBColor(0xE8, 0x79, 0x2F),
    "medium": RGBColor(0xB0, 0x8A, 0x00), "low": RGBColor(0x4F, 0x9E, 0xCF), "info": RGBColor(0x99, 0x99, 0x99),
}


def generate_docx_report(data: dict, output_path: str):
    doc = Document()
    report_type = data["report_type"]

    title = doc.add_heading(TITLES.get(report_type, "Vulnerability Assessment Report"), level=0)
    title.runs[0].font.color.rgb = BRAND_BLUE

    meta = doc.add_paragraph()
    meta.add_run(f"Generated {data['generated_at']} · Scope: {data['scope']}").italic = True

    doc.add_heading("Summary", level=1)
    s = data["summary"]
    table = doc.add_table(rows=2, cols=5)
    table.style = "Light Grid Accent 1"
    hdr = table.rows[0].cells
    for i, label in enumerate(["Assets", "Vulnerabilities", "Critical", "Known Exploited", "Exploit Available"]):
        hdr[i].text = label
    vals = table.rows[1].cells
    for i, v in enumerate([s["total_assets"], s["total_vulnerabilities"], s["severity_counts"]["critical"], s["kev_count"], s["exploitable_count"]]):
        vals[i].text = str(v)

    if report_type == "executive":
        doc.add_heading("Executive Summary", level=1)
        summary_text = (
            f"This assessment identified {s['total_vulnerabilities']} vulnerabilities across "
            f"{s['total_assets']} assets, including {s['severity_counts']['critical']} critical and "
            f"{s['severity_counts']['high']} high severity findings."
        )
        if s["kev_count"] > 0:
            summary_text += (
                f" {s['kev_count']} of these are listed in the CISA Known Exploited Vulnerabilities "
                f"catalog, indicating active real-world exploitation and warranting urgent remediation."
            )
        doc.add_paragraph(summary_text)

        doc.add_heading("Severity Distribution", level=1)
        chart = doc.add_table(rows=1, cols=3)
        chart.style = "Light Grid Accent 1"
        for i, heading in enumerate(["Severity", "Findings", "Share"]):
            chart.rows[0].cells[i].text = heading
        total = max(s["total_vulnerabilities"], 1)
        for level in ("critical", "high", "medium", "low", "info"):
            row = chart.add_row().cells
            count = s["severity_counts"].get(level, 0)
            row[0].text = level.upper()
            row[1].text = str(count)
            row[2].text = f"{count / total:.1%}"

        doc.add_heading("Exposure Signals", level=1)
        exposure = doc.add_table(rows=1, cols=3)
        exposure.style = "Light Grid Accent 1"
        for i, heading in enumerate(["Signal", "Findings", "Share of Findings"]):
            exposure.rows[0].cells[i].text = heading
        for label, count in (("Known Exploited (CISA KEV)", s["kev_count"]), ("Exploit Available", s["exploitable_count"])):
            row = exposure.add_row().cells
            row[0].text, row[1].text, row[2].text = label, str(count), f"{count / total:.1%}"

        doc.add_heading("Top Risk Findings", level=1)
        t = doc.add_table(rows=1, cols=4)
        t.style = "Light Grid Accent 1"
        for i, h in enumerate(["Finding", "Severity", "Asset", "Risk Score"]):
            t.rows[0].cells[i].text = h
        for f in data["top_risk_findings"]:
            row = t.add_row().cells
            row[0].text, row[1].text, row[2].text, row[3].text = f["title"], f["severity"].upper(), f["asset_ip"], str(f["risk_score"])

        doc.add_heading("Most At-Risk Assets", level=1)
        t2 = doc.add_table(rows=1, cols=4)
        t2.style = "Light Grid Accent 1"
        for i, h in enumerate(["IP Address", "Hostname", "Criticality", "Max Risk"]):
            t2.rows[0].cells[i].text = h
        for a in data["critical_assets"]:
            row = t2.add_row().cells
            row[0].text, row[1].text, row[2].text, row[3].text = a["ip"], a.get("hostname") or "-", a["criticality"], str(a["max_risk_score"])

    elif report_type == "technical":
        doc.add_heading(f"Detailed Findings ({len(data['findings'])})", level=1)
        for f in data["findings"]:
            p = doc.add_heading(level=2)
            run = p.add_run(f["title"])
            run.font.size = Pt(13)
            sev_run = p.add_run(f"  [{f['severity'].upper()}]")
            sev_run.font.color.rgb = SEVERITY_COLORS.get(f["severity"], RGBColor(0, 0, 0))
            sev_run.bold = True

            meta_p = doc.add_paragraph()
            meta_p.add_run(
                f"{f['asset_ip']}{' (' + f['asset_hostname'] + ')' if f['asset_hostname'] else ''}"
                f"{':' + str(f['port']) if f['port'] else ''} · CVSS {f['cvss_score'] or 'n/a'} · "
                f"Risk {f['risk_score']} ({f['risk_band']})"
            ).italic = True

            doc.add_paragraph(f["description"] or "No description available.")

            tags = f["cve_ids"] + f["cwe_ids"] + f["attack_techniques"] + f["owasp_categories"]
            if f["kev_listed"]:
                tags.append("CISA KEV")
            if f["exploit_available"]:
                tags.append("Exploit Available")
            if tags:
                doc.add_paragraph(", ".join(tags)).italic = True

            rem_p = doc.add_paragraph()
            rem_p.add_run("Remediation: ").bold = True
            rem_p.add_run(f["remediation"])

            doc.add_paragraph(f"Detected by: {', '.join(f['source_scanners'])}").runs[0].font.size = Pt(9)

    elif report_type == "compliance":
        doc.add_heading(f"Compliance Mapping — {data.get('compliance_framework', '')}", level=1)
        t = doc.add_table(rows=1, cols=4)
        t.style = "Light Grid Accent 1"
        for i, h in enumerate(["Finding", "Severity", "Asset", "Mapped Controls"]):
            t.rows[0].cells[i].text = h
        for r in data.get("compliance_rows", []):
            row = t.add_row().cells
            row[0].text, row[1].text, row[2].text = r["finding"], r["severity"].upper(), r["asset_ip"]
            row[3].text = "; ".join(r["controls"])

    doc.save(output_path)
