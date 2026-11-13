import { useEffect, useState } from "react";
import { Plus, Trash2, Power } from "lucide-react";
import { api } from "../api/client";
import type { ScanSchedule } from "../types";
import { Card, Button, Input, Select, EmptyState } from "../components/ui";

export default function SchedulesPage() {
  const [schedules, setSchedules] = useState<ScanSchedule[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [scannerType, setScannerType] = useState("nmap");
  const [target, setTarget] = useState("");
  const [frequency, setFrequency] = useState("weekly");
  const [cron, setCron] = useState("");
  const [rescanOnRemediation, setRescanOnRemediation] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    load();
  }, []);

  function load() {
    api.get<{ schedules: ScanSchedule[] }>("/schedules").then((r) => setSchedules(r.schedules));
  }

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      await api.post("/schedules", {
        name,
        scanner_type: scannerType,
        target,
        frequency,
        cron_expression: frequency === "custom_cron" ? cron : undefined,
        rescan_on_remediation: rescanOnRemediation,
      });
      setShowForm(false);
      setName("");
      setTarget("");
      load();
    } catch (err: any) {
      alert(err.message || "Failed to create schedule");
    } finally {
      setBusy(false);
    }
  }

  async function toggle(id: number) {
    await api.patch(`/schedules/${id}/toggle`);
    load();
  }

  async function remove(id: number) {
    if (!confirm("Delete this recurring schedule?")) return;
    await api.del(`/schedules/${id}`);
    load();
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--text)]">
            Automated Scan Schedules
          </h1>
          <p className="text-xs text-[var(--text-muted)] mt-1">
            Configure periodic assessments, cron routines, and automatic re-scans upon remediation
          </p>
        </div>
        <Button
          onClick={() => setShowForm((s) => !s)}
          variant={showForm ? "secondary" : "primary"}
          size="sm"
          icon={Plus}
        >
          {showForm ? "Cancel" : "New Schedule"}
        </Button>
      </div>

      {showForm && (
        <Card
          header="Configure Recurring Scan Schedule"
          subtitle="APScheduler in-process background job registration"
        >
          <form onSubmit={create} className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-xs font-semibold text-[var(--text)] block mb-1.5">
                  Schedule Name
                </label>
                <Input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  required
                  placeholder="e.g. Weekly Perimeter Scan"
                  className="w-full text-xs"
                />
              </div>
              <div>
                <label className="text-xs font-semibold text-[var(--text)] block mb-1.5">
                  Scanner Engine
                </label>
                <Select
                  value={scannerType}
                  onChange={(e) => setScannerType(e.target.value)}
                  className="w-full text-xs font-mono-data"
                >
                  <option value="nmap">Nmap (Network & NSE)</option>
                  <option value="nuclei">Nuclei (Web Templates)</option>
                  <option value="openvas">OpenVAS (GMP Daemon)</option>
                  <option value="nessus">Nessus (REST Client)</option>
                  <option value="custom">Custom Script</option>
                </Select>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-xs font-semibold text-[var(--text)] block mb-1.5">
                  Target (IP, CIDR, or Hostname)
                </label>
                <Input
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  required
                  className="w-full font-mono-data text-xs"
                  placeholder="10.0.0.0/24"
                />
              </div>
              <div>
                <label className="text-xs font-semibold text-[var(--text)] block mb-1.5">
                  Recurrence Frequency
                </label>
                <Select
                  value={frequency}
                  onChange={(e) => setFrequency(e.target.value)}
                  className="w-full text-xs font-mono-data"
                >
                  <option value="daily">Daily Interval</option>
                  <option value="weekly">Weekly Routine</option>
                  <option value="monthly">Monthly Cycle</option>
                  <option value="custom_cron">Custom Cron Expression</option>
                </Select>
              </div>
            </div>

            {frequency === "custom_cron" && (
              <div>
                <label className="text-xs font-semibold text-[var(--text)] block mb-1.5">
                  Cron Expression (5-field UTC)
                </label>
                <Input
                  value={cron}
                  onChange={(e) => setCron(e.target.value)}
                  placeholder="0 2 * * 1"
                  className="w-full font-mono-data text-xs"
                />
              </div>
            )}

            <div className="p-3 bg-[var(--surface-2)] border border-[var(--border)] rounded-[5px] flex items-center gap-3">
              <input
                type="checkbox"
                id="rescan"
                checked={rescanOnRemediation}
                onChange={(e) => setRescanOnRemediation(e.target.checked)}
                className="w-4 h-4 accent-[var(--brand)] rounded cursor-pointer"
              />
              <label htmlFor="rescan" className="text-xs text-[var(--text)] cursor-pointer select-none">
                <strong>Auto-Rescan on Remediation:</strong> Automatically trigger a verification scan whenever a correlated finding is marked remediated.
              </label>
            </div>

            <div className="flex justify-end pt-2">
              <Button type="submit" disabled={busy} variant="primary" size="sm">
                {busy ? "Registering..." : "Activate Schedule"}
              </Button>
            </div>
          </form>
        </Card>
      )}

      {schedules.length === 0 ? (
        <Card>
          <EmptyState
            title="No automated schedules active"
            hint="Set up periodic scans to continuously monitor changes in your attack surface."
          />
        </Card>
      ) : (
        <Card className="p-0 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm min-w-[800px]">
              <thead>
                <tr className="border-b border-[var(--border)] bg-[var(--surface-2)]/40 font-mono-data uppercase text-xs text-[var(--text-dim)]">
                  <th className="text-left px-4 py-3">Schedule Name</th>
                  <th className="text-left px-4 py-3">Scanner</th>
                  <th className="text-left px-4 py-3">Target Scope</th>
                  <th className="text-left px-4 py-3">Frequency</th>
                  <th className="text-left px-4 py-3">Last Executed</th>
                  <th className="text-left px-4 py-3">State</th>
                  <th className="text-right px-4 py-3">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border-soft)]">
                {schedules.map((s) => (
                  <tr key={s.id} className="hover:bg-[var(--surface-2)]/30 transition-colors">
                    <td className="px-4 py-3 font-semibold text-[var(--text)]">{s.name}</td>
                    <td className="px-4 py-3 uppercase text-xs font-mono-data text-[var(--brand)]">
                      {s.scanner_type}
                    </td>
                    <td className="px-4 py-3 font-mono-data text-xs text-[var(--text-muted)]">
                      {s.target}
                    </td>
                    <td className="px-4 py-3 text-xs capitalize font-mono-data text-[var(--text)]">
                      {s.frequency.replace("_", " ")}
                    </td>
                    <td className="px-4 py-3 text-xs text-[var(--text-dim)] font-mono-data">
                      {s.last_run ? new Date(s.last_run).toLocaleString() : "Never"}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[10.5px] font-mono-data font-bold uppercase ${
                          s.enabled
                            ? "bg-[var(--brand-dim)] text-[var(--brand)]"
                            : "bg-[var(--surface-3)] text-[var(--text-dim)]"
                        }`}
                      >
                        <span
                          className={`w-1.5 h-1.5 rounded-full ${
                            s.enabled ? "bg-[var(--brand)]" : "bg-[var(--text-dim)]"
                          }`}
                        />
                        {s.enabled ? "Active" : "Paused"}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => toggle(s.id)}
                          className={`p-1.5 rounded transition-colors cursor-pointer ${
                            s.enabled
                              ? "text-[var(--text-dim)] hover:text-[var(--medium)] hover:bg-[var(--surface-2)]"
                              : "text-[var(--text-dim)] hover:text-[var(--brand)] hover:bg-[var(--surface-2)]"
                          }`}
                          title={s.enabled ? "Pause Schedule" : "Enable Schedule"}
                        >
                          <Power size={15} />
                        </button>
                        <button
                          onClick={() => remove(s.id)}
                          className="p-1.5 text-[var(--text-dim)] hover:text-[var(--critical)] hover:bg-[var(--critical-dim)] rounded transition-colors cursor-pointer"
                          title="Delete Schedule"
                        >
                          <Trash2 size={15} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}
