import { useEffect, useState } from "react";
import { FileText, Download } from "lucide-react";
import { api, downloadFile } from "../api/client";
import type { ReportJob } from "../types";
import { Card, Button, Select, EmptyState } from "../components/ui";

export default function ReportsPage() {
  const [reports, setReports] = useState<ReportJob[]>([]);
  const [reportType, setReportType] = useState("executive");
  const [reportFormat, setReportFormat] = useState("pdf");
  const [framework, setFramework] = useState("PCI-DSS");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    load();
  }, []);

  function load() {
    api.get<{ reports: ReportJob[] }>("/reports").then((r) => setReports(r.reports));
  }

  async function generate(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const resp = await api.post<{ report_id: number; download_url: string }>("/reports/generate", {
        report_type: reportType,
        report_format: reportFormat,
        compliance_framework: reportType === "compliance" ? framework : undefined,
      });
      load();
      await downloadFile(`/reports/${resp.report_id}/download`, `report.${reportFormat}`);
    } catch (err: any) {
      alert(err.message || "Report generation failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold">Reports</h1>
        <p className="text-sm text-[var(--text-muted)] mt-1">Executive, technical, and compliance reports for security teams and stakeholders</p>
      </div>

      <Card>
        <h3 className="text-xs uppercase tracking-wide text-[var(--text-muted)] mb-4">Generate a Report</h3>
        <form onSubmit={generate} className="flex gap-3 items-end flex-wrap">
          <div>
            <label className="text-xs text-[var(--text-muted)] block mb-1">Report Type</label>
            <Select value={reportType} onChange={(e) => setReportType(e.target.value)}>
              <option value="executive">Executive Summary</option>
              <option value="technical">Technical Detail</option>
              <option value="compliance">Compliance Mapping</option>
            </Select>
          </div>
          {reportType === "compliance" && (
            <div>
              <label className="text-xs text-[var(--text-muted)] block mb-1">Framework</label>
              <Select value={framework} onChange={(e) => setFramework(e.target.value)}>
                <option value="PCI-DSS">PCI-DSS</option>
                <option value="ISO27001">ISO 27001</option>
                <option value="NIST_CSF">NIST CSF</option>
              </Select>
            </div>
          )}
          <div>
            <label className="text-xs text-[var(--text-muted)] block mb-1">Format</label>
            <Select value={reportFormat} onChange={(e) => setReportFormat(e.target.value)}>
              <option value="pdf">PDF</option>
              <option value="html">HTML</option>
              <option value="docx">DOCX</option>
              <option value="json">JSON</option>
            </Select>
          </div>
          <Button type="submit" disabled={busy} className="flex items-center gap-2">
            <FileText size={14} /> {busy ? "Generating..." : "Generate & Download"}
          </Button>
        </form>
      </Card>

      <Card>
        <h3 className="text-xs uppercase tracking-wide text-[var(--text-muted)] mb-4">Report History</h3>
        {reports.length === 0 ? (
          <EmptyState title="No reports generated yet" />
        ) : (
          <div className="space-y-2">
            {reports.map((r) => (
              <div key={r.id} className="flex items-center justify-between py-2.5 border-b border-[var(--border-soft)] last:border-0">
                <div>
                  <div className="text-sm font-medium capitalize">
                    {r.report_type} Report {r.compliance_framework && `— ${r.compliance_framework}`}
                  </div>
                  <div className="text-xs text-[var(--text-dim)]">
                    {new Date(r.generated_at).toLocaleString()} · {r.generated_by} · {r.scope_description}
                  </div>
                </div>
                <button
                  onClick={() => downloadFile(`/reports/${r.id}/download`, `report.${r.report_format}`).catch((err) => alert(err.message))}
                  className="flex items-center gap-1.5 text-xs text-[var(--brand)] hover:underline uppercase font-semibold"
                >
                  <Download size={13} /> {r.report_format}
                </button>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
