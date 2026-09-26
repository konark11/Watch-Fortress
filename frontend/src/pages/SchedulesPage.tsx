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
        name, scanner_type: scannerType, target, frequency,
        cron_expression: frequency === "custom_cron" ? cron : undefined,
        rescan_on_remediation: rescanOnRemediation,
      });
      setShowForm(false);
      setName("");
      setTarget("");
      load();
    } catch (err: any) {
      alert(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function toggle(id: number) {
    await api.patch(`/schedules/${id}/toggle`);
    load();
  }

  async function remove(id: number) {
    if (!confirm("Delete this schedule?")) return;
    await api.del(`/schedules/${id}`);
    load();
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">Scan Schedules</h1>
          <p className="text-sm text-[var(--text-muted)] mt-1">Continuous scanning — daily, weekly, monthly, or custom cron</p>
        </div>
        <Button onClick={() => setShowForm((s) => !s)} className="flex items-center gap-2">
          <Plus size={14} /> New Schedule
        </Button>
      </div>

      {showForm && (
        <Card>
          <form onSubmit={create} className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs text-[var(--text-muted)] block mb-1">Name</label>
                <Input value={name} onChange={(e) => setName(e.target.value)} required className="w-full" />
              </div>
              <div>
                <label className="text-xs text-[var(--text-muted)] block mb-1">Scanner</label>
                <Select value={scannerType} onChange={(e) => setScannerType(e.target.value)} className="w-full">
                  <option value="nmap">Nmap</option>
                  <option value="openvas">OpenVAS</option>
                  <option value="nessus">Nessus</option>
                  <option value="nuclei">Nuclei</option>
                  <option value="custom">Custom Script</option>
                </Select>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs text-[var(--text-muted)] block mb-1">Target</label>
                <Input value={target} onChange={(e) => setTarget(e.target.value)} required className="w-full" placeholder="10.0.0.0/24" />
              </div>
              <div>
                <label className="text-xs text-[var(--text-muted)] block mb-1">Frequency</label>
                <Select value={frequency} onChange={(e) => setFrequency(e.target.value)} className="w-full">
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                  <option value="monthly">Monthly</option>
                  <option value="custom_cron">Custom (cron)</option>
                </Select>
              </div>
            </div>
            {frequency === "custom_cron" && (
              <div>
                <label className="text-xs text-[var(--text-muted)] block mb-1">Cron Expression</label>
                <Input value={cron} onChange={(e) => setCron(e.target.value)} placeholder="0 2 * * 1" className="w-full font-mono-data" />
              </div>
            )}
            <label className="flex items-center gap-2 text-sm text-[var(--text-muted)]">
              <input type="checkbox" checked={rescanOnRemediation} onChange={(e) => setRescanOnRemediation(e.target.checked)} />
              Automatically re-scan when a finding from this schedule is marked remediated
            </label>
            <Button type="submit" disabled={busy}>{busy ? "Saving..." : "Create Schedule"}</Button>
          </form>
        </Card>
      )}

      {schedules.length === 0 ? (
        <Card><EmptyState title="No schedules configured" hint="Set up recurring scans so your inventory stays current automatically." /></Card>
      ) : (
        <Card className="p-0 overflow-hidden">
          <div className="overflow-x-auto">
          <table className="w-full text-sm min-w-[800px]">
            <thead>
              <tr className="border-b border-[var(--border)]">
                {["Name", "Scanner", "Target", "Frequency", "Last Run", "Status", ""].map((h) => (
                  <th key={h} className="text-left text-xs text-[var(--text-dim)] font-medium px-4 py-3">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {schedules.map((s) => (
                <tr key={s.id} className="border-b border-[var(--border-soft)] last:border-0">
                  <td className="px-4 py-3">{s.name}</td>
                  <td className="px-4 py-3 uppercase text-xs font-mono-data text-[var(--text-muted)]">{s.scanner_type}</td>
                  <td className="px-4 py-3 font-mono-data text-xs">{s.target}</td>
                  <td className="px-4 py-3 capitalize">{s.frequency.replace("_", " ")}</td>
                  <td className="px-4 py-3 text-xs text-[var(--text-muted)]">{s.last_run ? new Date(s.last_run).toLocaleString() : "Never"}</td>
                  <td className="px-4 py-3">
                    <span className={`text-xs px-2 py-0.5 rounded ${s.enabled ? "bg-[var(--brand-dim)] text-[var(--brand)]" : "bg-[var(--surface-2)] text-[var(--text-dim)]"}`}>
                      {s.enabled ? "Enabled" : "Disabled"}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex gap-2">
                      <button onClick={() => toggle(s.id)} className="text-[var(--text-muted)] hover:text-[var(--brand)]"><Power size={14} /></button>
                      <button onClick={() => remove(s.id)} className="text-[var(--text-muted)] hover:text-[var(--critical)]"><Trash2 size={14} /></button>
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
