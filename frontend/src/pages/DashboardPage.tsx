import { useEffect, useState } from "react";
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from "recharts";
import {
  Server,
  ShieldAlert,
  Globe,
  Flame,
  Zap,
  Radar,
  ArrowRight,
} from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { DashboardStats } from "../types";
import { Card, KpiCard, StatusBadge, Button } from "../components/ui";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#c85a54",
  high: "#d97736",
  medium: "#c99738",
  low: "#5a949b",
  info: "#787f8a",
};

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .get<DashboardStats>("/dashboard/stats")
      .then(setStats)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading || !stats) {
    return (
      <div className="space-y-5 animate-pulse">
        <div className="h-6 bg-[var(--surface-2)] rounded-[5px] w-48" />
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="h-20 bg-[var(--surface)] border border-[var(--border)] rounded-[5px]" />
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          <div className="h-64 bg-[var(--surface)] border border-[var(--border)] rounded-[5px]" />
          <div className="h-64 bg-[var(--surface)] border border-[var(--border)] rounded-[5px]" />
        </div>
      </div>
    );
  }

  const severityData = Object.entries(stats.by_severity)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }));

  const totalFindings = severityData.reduce((acc, curr) => acc + curr.value, 0);

  const heatmapByCrit: Record<string, Record<string, number>> = {};
  for (const row of stats.risk_heatmap) {
    heatmapByCrit[row.criticality] ??= {};
    heatmapByCrit[row.criticality][row.severity] = row.count;
  }
  const criticalities = ["critical", "high", "medium", "low"];
  const severities = ["critical", "high", "medium", "low", "info"];

  return (
    <div className="space-y-5">
      {/* Title & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-base font-semibold text-[var(--text)]">
            Overview
          </h1>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">
            Correlated vulnerabilities, asset exposures, and taxonomy mappings.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Link to="/scans">
            <Button size="sm" variant="primary" icon={Radar}>
              Run scan
            </Button>
          </Link>
          <Link to="/vulnerabilities">
            <Button size="sm" variant="secondary" icon={ShieldAlert}>
              View findings
            </Button>
          </Link>
        </div>
      </div>

      {/* KPI Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <KpiCard
          label="Assets"
          value={stats.total_assets}
          icon={Server}
          badge="discovered"
        />
        <KpiCard
          label="Vulnerabilities"
          value={stats.total_vulnerabilities}
          icon={ShieldAlert}
          accent={stats.total_vulnerabilities > 0 ? "var(--high)" : undefined}
          badge="correlated"
        />
        <KpiCard
          label="Internet exposed"
          value={stats.internet_exposed_assets}
          icon={Globe}
          accent="var(--high)"
          badge="public"
        />
        <KpiCard
          label="Known exploited"
          value={stats.kev_count}
          icon={Flame}
          accent="var(--critical)"
          badge="CISA KEV"
        />
        <KpiCard
          label="Exploit public"
          value={stats.exploitable_count}
          icon={Zap}
          accent="var(--medium)"
          badge="verified"
        />
        <KpiCard
          label="Scans completed"
          value={stats.total_scans}
          icon={Radar}
          badge="history"
        />
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Severity Distribution Donut */}
        <Card
          header="Findings by severity"
          subtitle="Normalized risk tier distribution"
        >
          <div className="relative">
            <ResponsiveContainer width="100%" height={210}>
              <PieChart>
                <Pie
                  data={severityData}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={60}
                  outerRadius={84}
                  paddingAngle={2}
                  stroke="#18191d"
                  strokeWidth={2}
                >
                  {severityData.map((entry) => (
                    <Cell
                      key={entry.name}
                      fill={SEVERITY_COLORS[entry.name] || "#787f8a"}
                    />
                  ))}
                </Pie>
                <Tooltip
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const data = payload[0];
                      const name = data.name as string;
                      const value = data.value as number;
                      const pct = totalFindings > 0 ? Math.round((value / totalFindings) * 100) : 0;
                      return (
                        <div className="bg-[var(--surface-2)] border border-[var(--border)] rounded-[4px] p-2 text-xs">
                          <div className="flex items-center gap-1.5 mb-1">
                            <span
                              className="w-2 h-2 rounded-full"
                              style={{ background: SEVERITY_COLORS[name] }}
                            />
                            <span className="font-medium capitalize text-[var(--text)]">{name}</span>
                          </div>
                          <div className="text-[var(--text-secondary)] font-mono-data">
                            {value} ({pct}%)
                          </div>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-2xl font-medium font-mono-data text-[var(--text)]">
                {totalFindings}
              </span>
              <span className="text-[10px] text-[var(--text-tertiary)]">
                Total
              </span>
            </div>
          </div>

          <div className="flex flex-wrap gap-4 justify-center mt-2 pt-2 border-t border-[var(--border)]">
            {severityData.map((e) => (
              <div
                key={e.name}
                className="flex items-center gap-1.5 text-xs text-[var(--text-secondary)]"
              >
                <span
                  className="w-1.5 h-1.5 rounded-full"
                  style={{ background: SEVERITY_COLORS[e.name] }}
                />
                <span className="capitalize">{e.name}</span>
                <span className="font-mono-data text-[var(--text-tertiary)]">({e.value})</span>
              </div>
            ))}
          </div>
        </Card>

        {/* MITRE ATT&CK Techniques Bar Chart */}
        <Card
          header="Top MITRE ATT&CK techniques"
          subtitle="Observed adversarial capabilities mapped via offline taxonomy"
        >
          {stats.technique_heatmap.length === 0 ? (
            <div className="text-xs text-[var(--text-tertiary)] py-16 text-center">
              No technique mappings recorded yet.
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={240}>
              <BarChart
                data={stats.technique_heatmap}
                layout="vertical"
                margin={{ left: 10, right: 15, top: 5, bottom: 5 }}
              >
                <CartesianGrid stroke="rgba(255, 255, 255, 0.04)" horizontal={false} />
                <XAxis
                  type="number"
                  tick={{ fill: "var(--text-tertiary)", fontSize: 10, fontFamily: "var(--mono)" }}
                  axisLine={{ stroke: "var(--border)" }}
                  tickLine={false}
                />
                <YAxis
                  type="category"
                  dataKey="technique"
                  tick={{ fill: "var(--text-secondary)", fontSize: 11, fontFamily: "var(--mono)" }}
                  width={70}
                  axisLine={{ stroke: "var(--border)" }}
                  tickLine={false}
                />
                <Tooltip
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const item = payload[0].payload as any;
                      return (
                        <div className="bg-[var(--surface-2)] border border-[var(--border)] rounded-[4px] p-2 text-xs">
                          <div className="text-[var(--accent)] font-medium font-mono-data">{item.technique}</div>
                          <div className="text-[var(--text)] mt-0.5">{item.name}</div>
                          <div className="text-[var(--text-secondary)] font-mono-data mt-1 pt-1 border-t border-[var(--border)]">
                            Findings: {item.count}
                          </div>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
                <Bar
                  dataKey="count"
                  fill="var(--accent)"
                  radius={[0, 2, 2, 0]}
                  maxBarSize={14}
                />
              </BarChart>
            </ResponsiveContainer>
          )}
        </Card>
      </div>

      {/* Risk Exposure Matrix */}
      <Card
        header="Risk exposure matrix"
        subtitle="Cross-tabulation of asset criticality against finding severity"
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-[var(--border)] text-[var(--text-tertiary)]">
                <th className="py-2 font-normal">Asset criticality</th>
                {severities.map((s) => (
                  <th
                    key={s}
                    className="py-2 text-center font-normal capitalize"
                  >
                    <span className="inline-flex items-center gap-1.5">
                      <span
                        className="w-1.5 h-1.5 rounded-full"
                        style={{ background: SEVERITY_COLORS[s] }}
                      />
                      {s}
                    </span>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border)]">
              {criticalities.map((crit) => (
                <tr key={crit} className="hover:bg-[var(--surface-hover)] transition-colors">
                  <td className="py-2 capitalize text-[var(--text-secondary)] font-medium">
                    {crit}
                  </td>
                  {severities.map((sev) => {
                    const count = heatmapByCrit[crit]?.[sev] || 0;
                    return (
                      <td key={sev} className="text-center py-2 font-mono-data">
                        {count > 0 ? (
                          <span
                            className="inline-block px-1.5 py-0.5 rounded-[3px] text-xs font-medium"
                            style={{
                              color: SEVERITY_COLORS[sev],
                              background: `${SEVERITY_COLORS[sev]}14`,
                            }}
                          >
                            {count}
                          </span>
                        ) : (
                          <span className="text-[var(--text-tertiary)]">–</span>
                        )}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Recent Activity List */}
      <Card
        header="Recent activity"
        subtitle="Latest scanner runs and imported reports"
        action={
          <Link
            to="/scans"
            className="text-xs text-[var(--text-secondary)] hover:text-[var(--text)] inline-flex items-center gap-1"
          >
            All scans <ArrowRight size={12} />
          </Link>
        }
      >
        {stats.recent_scans.length === 0 ? (
          <div className="text-xs text-[var(--text-tertiary)] py-6 text-center">
            No recent scans recorded.
          </div>
        ) : (
          <div className="divide-y divide-[var(--border)]">
            {stats.recent_scans.map((s) => (
              <div
                key={s.id}
                className="py-2.5 flex items-center justify-between gap-4"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <span className="font-mono-data text-[11px] uppercase text-[var(--text-tertiary)] w-14 shrink-0">
                    {s.scanner_type}
                  </span>
                  <span className="text-xs font-normal text-[var(--text)] truncate">
                    {s.name}
                  </span>
                </div>
                <div className="flex items-center gap-4 shrink-0 text-xs">
                  <span className="font-mono-data text-[var(--text-secondary)]">
                    {s.findings_count} findings
                  </span>
                  <StatusBadge status={s.status} />
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
