import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { Vulnerability } from "../types";
import { Card, EmptyState, SeverityBadge, Tag, Select, Input } from "../components/ui";

interface VulnDetail {
  id: number; title: string; description: string; severity: string; cvss_score: number | null;
  risk_score: number; cve_ids: string[]; cwe_ids: string[]; capec_ids: string[];
  attack_techniques: string[]; owasp_categories: string[]; exploit_available: boolean; kev_listed: boolean;
  remediation: string; status: string; assigned_to: string | null;
  asset: { id: number; ip_address: string; hostname: string | null } | null;
  port: number | null; source_scanners: string[];
  contributing_findings: { id: number; scanner: string; title: string; plugin_id: string }[];
}

export default function VulnerabilitiesPage() {
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [total, setTotal] = useState(0);
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<VulnDetail | null>(null);

  useEffect(() => {
    load();
  }, [severity, status]);

  function load() {
    const params = new URLSearchParams();
    if (severity) params.set("severity", severity);
    if (status) params.set("status", status);
    if (search) params.set("search", search);
    api.get<{ vulnerabilities: Vulnerability[]; total: number }>(`/vulnerabilities?${params}`).then((r) => {
      setVulns(r.vulnerabilities);
      setTotal(r.total);
    });
  }

  function openDetail(id: number) {
    api.get<VulnDetail>(`/vulnerabilities/${id}`).then(setSelected);
  }

  async function updateStatus(id: number, newStatus: string) {
    await api.patch(`/vulnerabilities/${id}/status`, { status: newStatus });
    load();
    if (selected?.id === id) openDetail(id);
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold">Vulnerabilities</h1>
        <p className="text-sm text-[var(--text-muted)] mt-1">{total} correlated, deduplicated findings across all scanners</p>
      </div>

      <div className="flex gap-3 items-center">
        <Select value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </Select>
        <Select value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">All statuses</option>
          <option value="open">Open</option>
          <option value="triaged">Triaged</option>
          <option value="remediated">Remediated</option>
          <option value="false_positive">False Positive</option>
          <option value="risk_accepted">Risk Accepted</option>
        </Select>
        <Input placeholder="Search title..." value={search} onChange={(e) => setSearch(e.target.value)} onKeyDown={(e) => e.key === "Enter" && load()} />
      </div>

      {vulns.length === 0 ? (
        <Card><EmptyState title="No vulnerabilities match these filters" /></Card>
      ) : (
        <Card className="p-0 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm min-w-[900px]">
              <thead>
                <tr className="border-b border-[var(--border)]">
                  {["Finding", "Severity", "Risk", "Asset", "CVEs", "Scanners", "Status"].map((h) => (
                    <th key={h} className="text-left text-xs text-[var(--text-dim)] font-medium px-4 py-3 whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {vulns.map((v) => (
                  <tr key={v.id} className="border-b border-[var(--border-soft)] last:border-0 hover:bg-[var(--surface-2)] cursor-pointer" onClick={() => openDetail(v.id)}>
                    <td className="px-4 py-3 max-w-xs truncate">{v.title}</td>
                    <td className="px-4 py-3 whitespace-nowrap"><SeverityBadge severity={v.severity} /></td>
                    <td className="px-4 py-3 font-mono-data font-semibold whitespace-nowrap">
                      {v.risk_score}
                      {v.kev_listed && <span className="ml-1.5 text-[9px] px-1 py-0.5 rounded bg-[var(--critical-dim)] text-[var(--critical)] font-bold">KEV</span>}
                    </td>
                    <td className="px-4 py-3 font-mono-data text-xs whitespace-nowrap">{v.asset_ip}{v.port ? `:${v.port}` : ""}</td>
                    <td className="px-4 py-3 text-xs whitespace-nowrap">{v.cve_ids.slice(0, 2).join(", ") || "—"}</td>
                    <td className="px-4 py-3 text-xs text-[var(--text-muted)] whitespace-nowrap">{v.source_scanners.join(", ")}</td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className="text-xs capitalize px-2 py-0.5 rounded bg-[var(--surface-2)] text-[var(--text-muted)]">{v.status.replace("_", " ")}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {selected && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-end z-50" onClick={() => setSelected(null)}>
          <div className="bg-[var(--surface)] border-l border-[var(--border)] w-[560px] h-full overflow-y-auto p-6" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-start justify-between mb-3">
              <div>
                <SeverityBadge severity={selected.severity} />
                <h2 className="text-lg font-bold mt-2">{selected.title}</h2>
              </div>
              <button onClick={() => setSelected(null)} className="text-[var(--text-muted)] hover:text-[var(--text)]">✕</button>
            </div>

            <div className="grid grid-cols-3 gap-3 mb-5">
              <Card className="p-3"><div className="text-xl font-bold font-mono-data">{selected.risk_score}</div><div className="text-[10px] text-[var(--text-muted)] uppercase">Risk Score</div></Card>
              <Card className="p-3"><div className="text-xl font-bold font-mono-data">{selected.cvss_score ?? "n/a"}</div><div className="text-[10px] text-[var(--text-muted)] uppercase">CVSS</div></Card>
              <Card className="p-3"><div className="text-xl font-bold font-mono-data">{selected.kev_listed ? "Yes" : "No"}</div><div className="text-[10px] text-[var(--text-muted)] uppercase">CISA KEV</div></Card>
            </div>

            <div className="mb-4">
              <label className="text-xs text-[var(--text-muted)] block mb-1.5">Status</label>
              <Select value={selected.status} onChange={(e) => updateStatus(selected.id, e.target.value)} className="w-full">
                <option value="open">Open</option>
                <option value="triaged">Triaged</option>
                <option value="remediated">Remediated</option>
                <option value="false_positive">False Positive</option>
                <option value="risk_accepted">Risk Accepted</option>
              </Select>
            </div>

            <p className="text-sm text-[var(--text-muted)] mb-4">{selected.description || "No description available."}</p>

            <div className="mb-4">
              {selected.cve_ids.map((c) => <Tag key={c} tone="critical">{c}</Tag>)}
              {selected.cwe_ids.map((c) => <Tag key={c}>{c}</Tag>)}
              {selected.capec_ids.map((c) => <Tag key={c}>{c}</Tag>)}
              {selected.attack_techniques.map((c) => <Tag key={c} tone="brand">{c}</Tag>)}
              {selected.owasp_categories.map((c) => <Tag key={c}>{c}</Tag>)}
            </div>

            <h4 className="text-xs uppercase tracking-wide text-[var(--text-muted)] mb-1.5">Remediation</h4>
            <p className="text-sm mb-5">{selected.remediation || "No specific remediation guidance recorded."}</p>

            <h4 className="text-xs uppercase tracking-wide text-[var(--text-muted)] mb-2">
              Contributing Findings ({selected.contributing_findings.length} scanner{selected.contributing_findings.length !== 1 ? "s" : ""})
            </h4>
            <div className="space-y-1.5">
              {selected.contributing_findings.map((f) => (
                <div key={f.id} className="bg-[var(--surface-2)] rounded-lg px-3 py-2 text-xs">
                  <span className="font-mono-data uppercase text-[var(--brand)] mr-2">{f.scanner}</span>
                  {f.title} <span className="text-[var(--text-dim)]">({f.plugin_id})</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
