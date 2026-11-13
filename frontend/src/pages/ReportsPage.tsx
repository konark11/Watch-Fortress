import { useEffect, useState } from "react";
import { Download } from "lucide-react";
import { api, downloadFile } from "../api/client";
import type { ReportRecord } from "../types";
import { Card, Button, Select, EmptyState } from "../components/ui";

const REPORT_TYPES = [
  { value: "technical", label: "Technical Remediation", desc: "Detailed host exposures, open ports, and patch commands" },
  { value: "executive", label: "Executive Summary", desc: "High-level risk posture, KPI charts, and threat landscape" },
  { value: "compliance", label: "Compliance Assessment", desc: "Audit mapping to PCI-DSS, ISO 27001, or NIST CSF" },
];

export default function ReportsPage() {
  const [reports, setReports] = useState<ReportRecord[]>([]);
  const [reportType, setReportType] = useState("technical");
  const [reportFormat, setReportFormat] = useState("pdf");
  const [framework, setFramework] = useState("PCI-DSS");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    load();
  }, []);

  function load() {
    api.get<{ reports: ReportRecord[] }>("/reports").then((r) => setReports(r.reports));
  }

  async function generate(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const resp = await api.post<{ report_id: number; download_url: string }>("/reports/generate", {
        report_type: reportType,
        format: reportFormat,
        scope: "all",
        compliance_framework: reportType === "compliance" ? framework : undefined,
      });
      await downloadFile(resp.download_url, `report_${reportType}.${reportFormat}`);
      load();
    } catch (err: any) {
      alert(err.message || "Failed to generate report");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      {/* Title */}
      <div>
        <h1 className="text-base font-semibold text-[var(--text)]">
          Reports
        </h1>
        <p className="text-xs text-[var(--text-secondary)] mt-0.5">
          Generate compliance dossiers, executive briefings, and technical remediation export files.
        </p>
      </div>

      {/* Generation Form Card */}
      <Card
        header="Generate report"
        subtitle="Select template scope and output format"
      >
        <form onSubmit={generate} className="space-y-3.5">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5">
            {REPORT_TYPES.map((t) => (
              <button
                key={t.value}
                type="button"
                onClick={() => setReportType(t.value)}
                className={`p-3 rounded-[5px] border text-left transition-colors cursor-pointer ${
                  reportType === t.value
                    ? "bg-[var(--surface-2)] border-[var(--border-strong)] text-[var(--text)] font-medium"
                    : "bg-[var(--surface)] border-[var(--border)] text-[var(--text-secondary)] hover:bg-[var(--surface-hover)]"
                }`}
              >
                <div className="text-xs font-medium text-[var(--text)] mb-0.5">{t.label}</div>
                <div className="text-[11px] text-[var(--text-tertiary)] leading-tight">{t.desc}</div>
              </button>
            ))}
          </div>

          <div className="flex flex-wrap items-end gap-3 pt-2 border-t border-[var(--border)]">
            {reportType === "compliance" && (
              <div>
                <label className="text-xs font-medium text-[var(--text)] block mb-1">
                  Framework
                </label>
                <Select
                  value={framework}
                  onChange={(e) => setFramework(e.target.value)}
                  className="w-44"
                >
                  <option value="PCI-DSS">PCI-DSS v4.0</option>
                  <option value="ISO27001">ISO/IEC 27001</option>
                  <option value="NIST_CSF">NIST CSF 2.0</option>
                </Select>
              </div>
            )}

            <div>
              <label className="text-xs font-medium text-[var(--text)] block mb-1">
                Output format
              </label>
              <Select
                value={reportFormat}
                onChange={(e) => setReportFormat(e.target.value)}
                className="w-40"
              >
                <option value="pdf">PDF Document</option>
                <option value="html">Interactive HTML</option>
                <option value="docx">Microsoft Word (DOCX)</option>
                <option value="json">Machine JSON</option>
              </Select>
            </div>

            <Button
              type="submit"
              disabled={busy}
              variant="primary"
              icon={Download}
            >
              {busy ? "Generating..." : "Generate report"}
            </Button>
          </div>
        </form>
      </Card>

      {/* Report History */}
      <Card
        header="Report archive"
        subtitle="Historical export documents"
      >
        {reports.length === 0 ? (
          <EmptyState
            title="No reports generated"
            hint="Generate a report above to create an export file."
          />
        ) : (
          <div className="divide-y divide-[var(--border)]">
            {reports.map((r) => (
              <div
                key={r.id}
                className="py-2.5 flex items-center justify-between gap-3 text-xs"
              >
                <div className="min-w-0">
                  <div className="font-medium text-[var(--text)] capitalize flex items-center gap-2">
                    <span>{r.report_type} report</span>
                    {r.compliance_framework && (
                      <span className="text-[10px] font-mono-data px-1.5 py-0.2 rounded bg-[var(--surface-2)] text-[var(--text-secondary)] uppercase">
                        {r.compliance_framework}
                      </span>
                    )}
                  </div>
                  <div className="text-[11px] text-[var(--text-tertiary)] font-mono-data mt-0.5">
                    {new Date(r.generated_at).toLocaleString()} · Operator: {r.generated_by || "System"}
                  </div>
                </div>

                <Button
                  size="sm"
                  variant="outline"
                  icon={Download}
                  onClick={() =>
                    downloadFile(`/reports/${r.id}/download`, `report.${r.report_format}`).catch(
                      (err) => alert(err.message),
                    )
                  }
                  className="font-mono-data uppercase shrink-0"
                >
                  {r.report_format}
                </Button>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
