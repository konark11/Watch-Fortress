import { useEffect, useState } from "react";
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";
import { api } from "../api/client";
import type { DashboardStats } from "../types";
import { Card, KpiCard } from "../components/ui";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#fb3f5e", high: "#fb923c", medium: "#fbbf24", low: "#38bdf8", info: "#64748b",
};

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);

  useEffect(() => {
    api.get<DashboardStats>("/dashboard/stats").then(setStats).catch(() => {});
  }, []);

  if (!stats) return <div className="text-[var(--text-muted)]">Loading...</div>;

  const severityData = Object.entries(stats.by_severity)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }));

  const heatmapByCrit: Record<string, Record<string, number>> = {};
  for (const row of stats.risk_heatmap) {
    heatmapByCrit[row.criticality] ??= {};
    heatmapByCrit[row.criticality][row.severity] = row.count;
  }
  const criticalities = ["critical", "high", "medium", "low"];
  const severities = ["critical", "high", "medium", "low", "info"];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold">Security Overview</h1>
        <p className="text-sm text-[var(--text-muted)] mt-1">Executive metrics across your entire attack surface</p>
      </div>

      <div className="flex gap-4 flex-wrap">
        <KpiCard label="Assets" value={stats.total_assets} />
        <KpiCard label="Vulnerabilities" value={stats.total_vulnerabilities} />
        <KpiCard label="Internet-Exposed Assets" value={stats.internet_exposed_assets} accent="var(--high)" />
        <KpiCard label="Known Exploited (CISA KEV)" value={stats.kev_count} accent="var(--critical)" />
        <KpiCard label="Exploit Available" value={stats.exploitable_count} accent="var(--high)" />
        <KpiCard label="Scans Run" value={stats.total_scans} accent="var(--brand)" />
      </div>

      <div className="grid grid-cols-2 gap-6">
        <Card>
          <h3 className="text-xs uppercase tracking-wide text-[var(--text-muted)] mb-4">Vulnerabilities by Severity</h3>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={severityData} dataKey="value" nameKey="name" innerRadius={55} outerRadius={85} paddingAngle={2}>
                {severityData.map((entry) => (
                  <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name]} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 8 }} />
            </PieChart>
          </ResponsiveContainer>
          <div className="flex flex-wrap gap-3 justify-center mt-2">
            {severityData.map((e) => (
              <div key={e.name} className="flex items-center gap-1.5 text-xs text-[var(--text-muted)]">
                <span className="w-2.5 h-2.5 rounded-full" style={{ background: SEVERITY_COLORS[e.name] }} />
                {e.name} ({e.value})
              </div>
            ))}
          </div>
        </Card>

        <Card>
          <h3 className="text-xs uppercase tracking-wide text-[var(--text-muted)] mb-4">Top MITRE ATT&amp;CK Techniques Observed</h3>
          {stats.technique_heatmap.length === 0 ? (
            <div className="text-sm text-[var(--text-dim)] py-16 text-center">No technique mappings yet — run or import a scan.</div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={stats.technique_heatmap} layout="vertical" margin={{ left: 10 }}>
                <CartesianGrid stroke="var(--border-soft)" horizontal={false} />
                <XAxis type="number" tick={{ fill: "var(--text-dim)", fontSize: 11 }} />
                <YAxis type="category" dataKey="technique" tick={{ fill: "var(--text-muted)", fontSize: 11 }} width={70} />
                <Tooltip
                  contentStyle={{ background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 8 }}
                  formatter={(value, _name, item) => [value, (item?.payload as any)?.name ?? ""]}
                />
                <Bar dataKey="count" fill="#2dd4bf" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </Card>
      </div>

      <Card>
        <h3 className="text-xs uppercase tracking-wide text-[var(--text-muted)] mb-4">Risk Heatmap — Asset Criticality × Finding Severity</h3>
        <table className="w-full text-sm">
          <thead>
            <tr>
              <th className="text-left text-xs text-[var(--text-dim)] font-medium pb-2">Asset Criticality</th>
              {severities.map((s) => (
                <th key={s} className="text-center text-xs text-[var(--text-dim)] font-medium pb-2 capitalize">{s}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {criticalities.map((crit) => (
              <tr key={crit} className="border-t border-[var(--border-soft)]">
                <td className="py-2.5 capitalize text-[var(--text-muted)]">{crit}</td>
                {severities.map((sev) => {
                  const count = heatmapByCrit[crit]?.[sev] || 0;
                  return (
                    <td key={sev} className="text-center py-2.5">
                      {count > 0 ? (
                        <span
                          className="inline-flex items-center justify-center w-8 h-8 rounded-lg font-mono-data text-xs font-bold"
                          style={{ background: `${SEVERITY_COLORS[sev]}22`, color: SEVERITY_COLORS[sev] }}
                        >
                          {count}
                        </span>
                      ) : (
                        <span className="text-[var(--text-dim)]">–</span>
                      )}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <Card>
        <h3 className="text-xs uppercase tracking-wide text-[var(--text-muted)] mb-4">Recent Scans</h3>
        {stats.recent_scans.length === 0 ? (
          <div className="text-sm text-[var(--text-dim)] py-6 text-center">No scans yet.</div>
        ) : (
          <div className="space-y-2">
            {stats.recent_scans.map((s) => (
              <div key={s.id} className="flex items-center justify-between py-2 border-b border-[var(--border-soft)] last:border-0">
                <div className="flex items-center gap-3">
                  <span className="font-mono-data text-xs text-[var(--text-dim)] uppercase">{s.scanner_type}</span>
                  <span className="text-sm">{s.name}</span>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-xs text-[var(--text-muted)]">{s.findings_count} findings</span>
                  <StatusPill status={s.status} />
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

function StatusPill({ status }: { status: string }) {
  const colorMap: Record<string, string> = {
    completed: "text-[var(--brand)] bg-[var(--brand-dim)]",
    running: "text-[var(--low)] bg-[var(--low-dim)]",
    failed: "text-[var(--critical)] bg-[var(--critical-dim)]",
    pending: "text-[var(--text-muted)] bg-[var(--surface-2)]",
    cancelled: "text-[var(--text-dim)] bg-[var(--surface-2)]",
  };
  return <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${colorMap[status] || ""}`}>{status}</span>;
}
