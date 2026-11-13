import { useEffect, useState, useCallback } from "react";
import { Copy, Check, Server } from "lucide-react";
import { api } from "../api/client";
import type { Vulnerability } from "../types";
import {
  Card,
  EmptyState,
  SeverityBadge,
  Tag,
  Select,
  SearchInput,
  Drawer,
  Button,
} from "../components/ui";

interface VulnDetail {
  id: number;
  title: string;
  description: string;
  severity: string;
  cvss_score: number | null;
  risk_score: number;
  status: string;
  remediation: string;
  cve_ids: string[];
  cwe_ids: string[];
  capec_ids: string[];
  attack_techniques: string[];
  owasp_categories: string[];
  kev_listed: boolean;
  port: number | null;
  asset: { id: number; ip_address: string; hostname: string } | null;
  contributing_findings: {
    id: number;
    scanner: string;
    plugin_id: string;
    title: string;
    severity: string;
  }[];
}

const SEVERITIES = [
  { value: "", label: "All severities" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
  { value: "info", label: "Info" },
];

const STATUSES = [
  { value: "", label: "All statuses" },
  { value: "open", label: "Open" },
  { value: "triaged", label: "Triaged" },
  { value: "remediated", label: "Remediated" },
  { value: "false_positive", label: "False positive" },
  { value: "risk_accepted", label: "Risk accepted" },
];

export default function VulnerabilitiesPage() {
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [total, setTotal] = useState(0);
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<VulnDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [copiedTag, setCopiedTag] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    const params = new URLSearchParams();
    if (severity) params.set("severity", severity);
    if (status) params.set("status", status);
    if (search) params.set("search", search);
    api
      .get<{ vulnerabilities: Vulnerability[]; total: number }>(`/vulnerabilities?${params}`)
      .then((r) => {
        setVulns(r.vulnerabilities);
        setTotal(r.total);
      })
      .finally(() => setLoading(false));
  }, [severity, status, search]);

  useEffect(() => {
    load();
  }, [load]);

  function openDetail(id: number) {
    api.get<VulnDetail>(`/vulnerabilities/${id}`).then(setSelected);
  }

  async function updateStatus(id: number, newStatus: string) {
    await api.patch(`/vulnerabilities/${id}/status`, { status: newStatus });
    load();
    if (selected?.id === id) openDetail(id);
  }

  function copyToClipboard(text: string) {
    navigator.clipboard.writeText(text);
    setCopiedTag(text);
    setTimeout(() => setCopiedTag(null), 2000);
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
        <div>
          <h1 className="text-base font-semibold text-[var(--text)]">
            Vulnerabilities
          </h1>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">
            <span className="font-mono-data text-[var(--text)]">{total}</span> correlated findings across all scanners.
          </p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center gap-2">
        {/* Severity filter */}
        <div className="flex items-center gap-1 bg-[var(--surface)] border border-[var(--border)] rounded-[5px] p-1 overflow-x-auto">
          {SEVERITIES.map((s) => (
            <button
              key={s.value}
              onClick={() => setSeverity(s.value)}
              className={`px-2.5 py-1 rounded-[4px] text-xs transition-colors cursor-pointer ${
                severity === s.value
                  ? "bg-[var(--surface-2)] text-[var(--text)] font-medium border border-[var(--border-strong)]"
                  : "text-[var(--text-secondary)] hover:text-[var(--text)] hover:bg-[var(--surface-hover)] border border-transparent"
              }`}
            >
              {s.label}
            </button>
          ))}
        </div>

        {/* Status Dropdown */}
        <Select
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          className="text-xs"
        >
          {STATUSES.map((s) => (
            <option key={s.value} value={s.value}>
              {s.label}
            </option>
          ))}
        </Select>

        {/* Search Input */}
        <div className="flex-1 min-w-[200px]">
          <SearchInput
            placeholder="Filter by title or CVE..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && load()}
            onClear={() => {
              setSearch("");
              setTimeout(load, 50);
            }}
          />
        </div>
      </div>

      {/* Main Table */}
      {loading ? (
        <Card className="p-8 text-center text-xs text-[var(--text-tertiary)] animate-pulse">
          Loading findings...
        </Card>
      ) : vulns.length === 0 ? (
        <Card>
          <EmptyState
            title="No vulnerabilities match the criteria"
            hint="Try clearing filters or running a new scan."
            action={
              (severity || status || search) && (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => {
                    setSeverity("");
                    setStatus("");
                    setSearch("");
                  }}
                >
                  Reset filters
                </Button>
              )
            }
          />
        </Card>
      ) : (
        <div className="bg-[var(--surface)] border border-[var(--border)] rounded-[5px] overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs min-w-[800px]">
              <thead className="sticky top-0 bg-[var(--surface-2)] border-b border-[var(--border)] text-[var(--text-secondary)]">
                <tr>
                  <th className="py-2 px-3 font-normal">Finding</th>
                  <th className="py-2 px-3 font-normal whitespace-nowrap">Severity</th>
                  <th className="py-2 px-3 font-normal whitespace-nowrap">Risk</th>
                  <th className="py-2 px-3 font-normal whitespace-nowrap">Target</th>
                  <th className="py-2 px-3 font-normal whitespace-nowrap">Identifiers</th>
                  <th className="py-2 px-3 font-normal whitespace-nowrap">Scanners</th>
                  <th className="py-2 px-3 font-normal whitespace-nowrap">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border)]">
                {vulns.map((v) => (
                  <tr
                    key={v.id}
                    onClick={() => openDetail(v.id)}
                    className="hover:bg-[var(--surface-hover)] cursor-pointer transition-colors"
                  >
                    <td className="py-2 px-3 font-medium text-[var(--text)] max-w-sm truncate">
                      {v.title}
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap">
                      <SeverityBadge severity={v.severity} />
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap font-mono-data">
                      <span className="text-[var(--text)] font-medium">{v.risk_score}</span>
                      {v.kev_listed && (
                        <span className="ml-1.5 text-[10px] text-[var(--critical)] font-sans">
                          KEV
                        </span>
                      )}
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap font-mono-data text-[var(--text-secondary)]">
                      <div className="flex items-center gap-1.5">
                        <Server size={12} className="text-[var(--text-tertiary)]" />
                        <span>{v.asset_ip}</span>
                        {v.port && <span className="text-[var(--text-tertiary)]">:{v.port}</span>}
                      </div>
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap font-mono-data text-[var(--text-secondary)]">
                      {v.cve_ids.length > 0 ? (
                        <span>
                          {v.cve_ids.slice(0, 2).join(", ")}
                          {v.cve_ids.length > 2 && (
                            <span className="text-[var(--text-tertiary)] ml-1">
                              +{v.cve_ids.length - 2}
                            </span>
                          )}
                        </span>
                      ) : (
                        <span className="text-[var(--text-tertiary)]">—</span>
                      )}
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap">
                      <div className="flex flex-wrap gap-1">
                        {v.source_scanners.map((sc) => (
                          <span
                            key={sc}
                            className="px-1.5 py-0.2 rounded-[3px] bg-[var(--surface-2)] text-[10px] font-mono-data uppercase text-[var(--text-tertiary)]"
                          >
                            {sc}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-2 px-3 whitespace-nowrap text-[var(--text-secondary)] capitalize">
                      {v.status.replace("_", " ")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Slide-over Detail Drawer */}
      <Drawer
        isOpen={Boolean(selected)}
        onClose={() => setSelected(null)}
        width="580px"
        title={
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              {selected && <SeverityBadge severity={selected.severity} />}
              {selected?.asset && (
                <span className="text-xs font-mono-data text-[var(--text-secondary)]">
                  {selected.asset.ip_address}
                  {selected.port ? `:${selected.port}` : ""}
                </span>
              )}
            </div>
            <div className="text-sm font-semibold text-[var(--text)] leading-snug">
              {selected?.title}
            </div>
          </div>
        }
      >
        {selected && (
          <div className="space-y-5 text-xs">
            {/* Score Strip */}
            <div className="grid grid-cols-3 gap-2">
              <div className="bg-[var(--surface-2)] border border-[var(--border)] rounded-[5px] p-2.5 text-center">
                <div className="text-lg font-medium font-mono-data text-[var(--text)]">
                  {selected.risk_score}
                </div>
                <div className="text-[11px] text-[var(--text-tertiary)]">
                  Calculated risk
                </div>
              </div>
              <div className="bg-[var(--surface-2)] border border-[var(--border)] rounded-[5px] p-2.5 text-center">
                <div className="text-lg font-medium font-mono-data text-[var(--text)]">
                  {selected.cvss_score ?? "—"}
                </div>
                <div className="text-[11px] text-[var(--text-tertiary)]">
                  CVSS base
                </div>
              </div>
              <div className="bg-[var(--surface-2)] border border-[var(--border)] rounded-[5px] p-2.5 text-center">
                <div
                  className={`text-lg font-medium font-mono-data ${
                    selected.kev_listed ? "text-[var(--critical)]" : "text-[var(--text-secondary)]"
                  }`}
                >
                  {selected.kev_listed ? "Active" : "None"}
                </div>
                <div className="text-[11px] text-[var(--text-tertiary)]">
                  CISA KEV
                </div>
              </div>
            </div>

            {/* Status Change Selector */}
            <div className="bg-[var(--surface-2)] border border-[var(--border)] rounded-[5px] p-3 flex items-center justify-between gap-4">
              <div>
                <span className="font-medium text-[var(--text)] block">
                  Triage status
                </span>
                <span className="text-[11px] text-[var(--text-tertiary)]">
                  Workflow disposition
                </span>
              </div>
              <Select
                value={selected.status}
                onChange={(e) => updateStatus(selected.id, e.target.value)}
                className="w-40"
              >
                <option value="open">Open</option>
                <option value="triaged">Triaged</option>
                <option value="remediated">Remediated</option>
                <option value="false_positive">False positive</option>
                <option value="risk_accepted">Risk accepted</option>
              </Select>
            </div>

            {/* Description */}
            <div>
              <div className="font-medium text-[var(--text)] mb-1">
                Summary
              </div>
              <div className="bg-[var(--surface-2)] border border-[var(--border)] rounded-[5px] p-3 text-[var(--text-secondary)] leading-relaxed">
                {selected.description || "No description recorded by the scanner."}
              </div>
            </div>

            {/* Taxonomy & ATT&CK Mapping */}
            <div>
              <div className="font-medium text-[var(--text)] mb-1.5">
                Taxonomy and identifiers
              </div>
              <div className="flex flex-wrap gap-1.5">
                {selected.cve_ids.map((c) => (
                  <button
                    key={c}
                    type="button"
                    onClick={() => copyToClipboard(c)}
                    className="inline-flex items-center gap-1 cursor-pointer"
                    title="Click to copy CVE"
                  >
                    <Tag tone="critical">
                      {c} {copiedTag === c ? <Check size={10} /> : <Copy size={10} />}
                    </Tag>
                  </button>
                ))}
                {selected.attack_techniques.map((c) => (
                  <button
                    key={c}
                    type="button"
                    onClick={() => copyToClipboard(c)}
                    className="inline-flex items-center gap-1 cursor-pointer"
                    title="Click to copy ATT&CK technique"
                  >
                    <Tag tone="brand">
                      {c} {copiedTag === c ? <Check size={10} /> : <Copy size={10} />}
                    </Tag>
                  </button>
                ))}
                {selected.cwe_ids.map((c) => (
                  <Tag key={c}>{c}</Tag>
                ))}
                {selected.capec_ids.map((c) => (
                  <Tag key={c}>{c}</Tag>
                ))}
                {selected.owasp_categories.map((c) => (
                  <Tag key={c}>{c}</Tag>
                ))}
              </div>
            </div>

            {/* Remediation Guidance */}
            <div>
              <div className="font-medium text-[var(--text)] mb-1">
                Remediation
              </div>
              <div className="bg-[var(--surface-2)] border border-[var(--border)] rounded-[5px] p-3 text-[var(--text)] font-mono-data leading-relaxed">
                {selected.remediation || "No remediation recorded."}
              </div>
            </div>

            {/* Contributing Findings */}
            <div>
              <div className="font-medium text-[var(--text)] mb-1.5">
                Contributing scanner findings ({selected.contributing_findings.length})
              </div>
              <div className="space-y-1.5">
                {selected.contributing_findings.map((f) => (
                  <div
                    key={f.id}
                    className="bg-[var(--surface-2)] border border-[var(--border)] rounded-[5px] p-2.5 flex items-center justify-between gap-3 text-xs"
                  >
                    <div className="min-w-0">
                      <span className="font-mono-data text-[11px] text-[var(--text-tertiary)] uppercase mr-2">
                        {f.scanner}
                      </span>
                      <span className="text-[var(--text)]">{f.title}</span>
                    </div>
                    <span className="font-mono-data text-[11px] text-[var(--text-tertiary)] shrink-0">
                      {f.plugin_id}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
}
