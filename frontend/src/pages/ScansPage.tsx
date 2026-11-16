import { useEffect, useRef, useState } from "react";
import { Play, FileUp, Square } from "lucide-react";
import { api } from "../api/client";
import type { Scan, WorkerReadiness } from "../types";
import { Card, Button, Input, Select, EmptyState, StatusBadge } from "../components/ui";

const ENGINES = [
  { id: "nmap", name: "Nmap", role: "Port and service detection", defaultScope: "IP, CIDR" },
  { id: "nuclei", name: "Nuclei", role: "Vulnerability and CVE templates", defaultScope: "URL, IP:Port" },
  { id: "openvas", name: "OpenVAS", role: "Full network vulnerability daemon", defaultScope: "Subnet" },
  { id: "nessus", name: "Nessus", role: "Commercial scanner client", defaultScope: "Enterprise" },
];

const NMAP_PROFILES = [
  { value: "vuln_scripts", label: "NSE vulnerability scripts (-sV --script vulners)" },
  { value: "service_version", label: "Service detection (-sV)" },
  { value: "quick", label: "Fast port discovery (Top 100 ports)" },
  { value: "full", label: "Standard 1,000 ports" },
  { value: "all_ports", label: "All 65,535 ports (-p-)" },
];

const NUCLEI_SEVERITY_PROFILES = [
  { value: "standard", label: "Standard (low, medium, high, critical)" },
  { value: "critical_high", label: "Critical and High only" },
  { value: "all", label: "All severities (including info)" },
];

export default function ScansPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [availability, setAvailability] = useState<Record<string, boolean>>({});
  const [workerReadiness, setWorkerReadiness] = useState<WorkerReadiness | null>(null);
  const [selectedEngines, setSelectedEngines] = useState<string[]>(["nmap"]);
  const [target, setTarget] = useState("192.168.1.0/24");
  const [name, setName] = useState("Internal Network Baseline");
  const [nmapProfile, setNmapProfile] = useState("vuln_scripts");
  const [nucleiSeverity, setNucleiSeverity] = useState("all");
  const [nucleiTags, setNucleiTags] = useState("");
  const [nucleiAutomaticScan, setNucleiAutomaticScan] = useState(false);
  const [launching, setLaunching] = useState(false);
  const [stopping, setStopping] = useState<Record<number, boolean>>({});
  const [progress, setProgress] = useState<Record<number, { pct: number; message: string; job_state?: string; findings_count?: number }>>({});
  const wsRefs = useRef<Record<number, WebSocket>>({});

  useEffect(() => {
    load();
    api.get<Record<string, boolean>>("/scans/scanner-availability").then(setAvailability);
    api.get<WorkerReadiness>("/scans/worker-readiness").then(setWorkerReadiness).catch(() => setWorkerReadiness(null));
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
  }, []);

  function load() {
    api.get<{ scans: Scan[] }>("/scans").then((r) => {
      setScans(r.scans);
      r.scans
        .filter((s) => (s.status === "pending" || s.status === "running") && !wsRefs.current[s.id])
        .forEach((s) => watchProgress(s.id));
    });
  }

  function watchProgress(scanId: number) {
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${proto}//${window.location.host}/ws/scans/${scanId}`);
    wsRefs.current[scanId] = ws;
    ws.onmessage = (evt) => {
      const data = JSON.parse(evt.data);
      setProgress((p) => ({ ...p, [scanId]: data }));
      if (data.pct >= 100) {
        ws.close();
        delete wsRefs.current[scanId];
        setTimeout(load, 500);
      }
    };
    ws.onerror = () => ws.close();
  }

  async function stopScan(scanId: number) {
    setStopping((current) => ({ ...current, [scanId]: true }));
    try {
      await api.post(`/scans/${scanId}/cancel`);
      const ws = wsRefs.current[scanId];
      if (ws) {
        ws.close();
        delete wsRefs.current[scanId];
      }
      await load();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Unable to stop scan.");
    } finally {
      setStopping((current) => {
        const next = { ...current };
        delete next[scanId];
        return next;
      });
    }
  }

  async function launch(e: React.FormEvent) {
    e.preventDefault();
    if (selectedEngines.length === 0) {
      alert("Select at least one scanner engine.");
      return;
    }
    setLaunching(true);
    try {
      const results = await Promise.allSettled(
        selectedEngines.map(async (scannerType) => {
          const options: Record<string, unknown> =
            scannerType === "nmap"
              ? { profile: nmapProfile }
              : scannerType === "nuclei"
              ? {
                  severity_profile: nucleiSeverity,
                  automatic_scan: nucleiAutomaticScan,
                  ...(nucleiTags ? { tags: nucleiTags } : {}),
                }
              : {};
          const resp = await api.post<{ scan_id: number }>("/scans/launch", {
            name: name || `${scannerType} scan of ${target}`,
            scanner_type: scannerType,
            target,
            options,
          });
          watchProgress(resp.scan_id);
          return { scannerType, scanId: resp.scan_id };
        }),
      );
      const failed = results.filter((res): res is PromiseRejectedResult => res.status === "rejected");
      if (failed.length > 0) {
        const messages = failed.map(({ reason }) => reason instanceof Error ? reason.message : String(reason));
        alert(messages.join("\n"));
      }
      if (failed.length < results.length) {
        load();
      }
    } catch (err: any) {
      alert(err.message || "Failed to launch scan");
    } finally {
      setLaunching(false);
    }
  }

  async function handleImport(file: File, importScannerType: string) {
    const form = new FormData();
    form.append("scanner_type", importScannerType);
    form.append("name", file.name);
    form.append("file", file);
    await api.postForm("/scans/import", form);
    load();
  }

  return (
    <div className="space-y-5">
      {/* Page Title */}
      <div>
        <h1 className="text-base font-semibold text-[var(--text)]">
          Scans
        </h1>
        <p className="text-xs text-[var(--text-secondary)] mt-0.5">
          Execute live scans or import offline assessment files.
        </p>
      </div>

      {/* Engine Status: Compact table list */}
      <div className="bg-[var(--surface)] border border-[var(--border)] rounded-[5px] overflow-hidden">
        <div className="px-4 py-2 border-b border-[var(--border)] flex items-center justify-between text-xs">
          <span className="font-medium text-[var(--text)]">Scanner engines</span>
          <span className={workerReadiness?.ready ? "text-emerald-500" : "text-[var(--text-tertiary)]"}>
            {workerReadiness === null
              ? "Scan worker: checking"
              : workerReadiness.ready
              ? "Scan worker: ready"
              : "Scan worker: unavailable"}
          </span>
        </div>
        <div className="divide-y divide-[var(--border)]">
          {ENGINES.map((engine) => {
            const isAvailable = availability[engine.id];
            return (
              <div
                key={engine.id}
                className="px-4 py-2.5 flex items-center justify-between text-xs"
              >
                <div className="flex items-center gap-3">
                  <span className="font-medium text-[var(--text)] w-20">{engine.name}</span>
                  <span className="text-[var(--text-secondary)]">{engine.role}</span>
                </div>
                <div className="flex items-center gap-6">
                  <span className="text-[var(--text-tertiary)] font-mono-data text-[11px] hidden sm:inline">
                    {engine.defaultScope}
                  </span>
                  <div className="flex items-center gap-1.5 w-28 justify-end">
                    <span
                      className={`w-1.5 h-1.5 rounded-full ${
                        isAvailable ? "bg-emerald-500" : "bg-[var(--text-tertiary)]"
                      }`}
                    />
                    <span className="text-[var(--text-secondary)]">
                      {isAvailable ? "Available" : "Not configured"}
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Side-by-side: Run a scan & Import a report */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Run a scan */}
        <Card
          header="Run a scan"
          subtitle="Dispatch live scanning jobs against designated network assets"
        >
          <form onSubmit={launch} className="space-y-3.5">
            <div>
              <label className="text-xs font-medium text-[var(--text)] block mb-1">
                Engines
              </label>
              <div className="flex flex-wrap gap-2">
                {ENGINES.slice(0, 3).map((engine) => {
                  const isChecked = selectedEngines.includes(engine.id);
                  const isAvail = availability[engine.id];
                  return (
                    <label
                      key={engine.id}
                      className={`inline-flex items-center gap-2 px-2.5 py-1.5 rounded-[5px] border text-xs cursor-pointer select-none transition-colors ${
                        isChecked
                          ? "bg-[var(--surface-2)] border-[var(--border-strong)] text-[var(--text)]"
                          : "bg-[var(--surface)] border-[var(--border)] text-[var(--text-secondary)] hover:bg-[var(--surface-hover)]"
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setSelectedEngines((prev) => [...prev, engine.id]);
                          } else {
                            setSelectedEngines((prev) => prev.filter((id) => id !== engine.id));
                          }
                        }}
                        className="rounded border-[var(--border)] w-3 h-3 text-[var(--accent)]"
                      />
                      <span>{engine.name}</span>
                      {isAvail === false && (
                        <span className="text-[10px] text-[var(--text-tertiary)]">
                          (unconfigured)
                        </span>
                      )}
                    </label>
                  );
                })}
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-xs font-medium text-[var(--text)]">
                  Target
                </label>
                <div className="flex items-center gap-1.5 text-[11px] text-[var(--text-tertiary)] font-mono-data">
                  <span>Samples:</span>
                  <button
                    type="button"
                    onClick={() => setTarget("192.168.1.0/24")}
                    className="hover:text-[var(--text)] cursor-pointer underline"
                  >
                    192.168.1.0/24
                  </button>
                  <button
                    type="button"
                    onClick={() => setTarget("10.0.0.1")}
                    className="hover:text-[var(--text)] cursor-pointer underline"
                  >
                    10.0.0.1
                  </button>
                </div>
              </div>
              <Input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder={
                  selectedEngines.includes("nuclei") && !selectedEngines.includes("nmap")
                    ? "https://target.local or http://192.168.1.10:8080"
                    : "192.168.1.0/24 or hostname"
                }
                required
                className="font-mono-data"
              />
            </div>

            <div>
              <label className="text-xs font-medium text-[var(--text)] block mb-1">
                Job name
              </label>
              <Input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Internal Network Baseline"
              />
            </div>

            {selectedEngines.includes("nmap") && (
              <div>
                <label className="text-xs font-medium text-[var(--text)] block mb-1">
                  Nmap profile
                </label>
                <Select
                  value={nmapProfile}
                  onChange={(e) => setNmapProfile(e.target.value)}
                  className="w-full"
                >
                  {NMAP_PROFILES.map((p) => (
                    <option key={p.value} value={p.value}>
                      {p.label}
                    </option>
                  ))}
                </Select>
              </div>
            )}

            {selectedEngines.includes("nuclei") && (
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs font-medium text-[var(--text)] block mb-1">
                    Nuclei severity
                  </label>
                  <Select
                    value={nucleiSeverity}
                    onChange={(e) => setNucleiSeverity(e.target.value)}
                    className="w-full"
                  >
                    {NUCLEI_SEVERITY_PROFILES.map((p) => (
                      <option key={p.value} value={p.value}>
                        {p.label}
                      </option>
                    ))}
                  </Select>
                </div>
                <div>
                  <label className="text-xs font-medium text-[var(--text)] block mb-1">
                    Tags (optional)
                  </label>
                  <Input
                    value={nucleiTags}
                    onChange={(e) => setNucleiTags(e.target.value)}
                    placeholder="cve, rce, ssl"
                  />
                </div>
                <label className="col-span-2 flex items-center gap-2 text-xs text-[var(--text-secondary)]">
                  <input
                    type="checkbox"
                    checked={nucleiAutomaticScan}
                    onChange={(e) => setNucleiAutomaticScan(e.target.checked)}
                  />
                  Automatic technology/CVE scan (-as)
                </label>
              </div>
            )}

            <div className="pt-2">
              <Button
                type="submit"
                disabled={launching || selectedEngines.length === 0 || workerReadiness?.ready === false}
                variant="primary"
                className="w-full"
                icon={Play}
              >
                Run scan
              </Button>
            </div>
          </form>
        </Card>

        {/* Import a report */}
        <Card
          header="Import a report"
          subtitle="Ingest scan artifacts from offline commercial or community scanners"
        >
          <div className="space-y-4">
            <div className="text-xs text-[var(--text-secondary)]">
              Supported formats: <span className="font-mono-data text-[var(--text)]">.xml (Nmap / OpenVAS), .nessus, .jsonl (Nuclei), .csv</span>
            </div>
            <ImportForm onImport={handleImport} />
          </div>
        </Card>
      </div>

      {/* Recent scans table */}
      <div className="bg-[var(--surface)] border border-[var(--border)] rounded-[5px] overflow-hidden">
        <div className="px-4 py-2.5 border-b border-[var(--border)] flex items-center justify-between">
          <span className="text-xs font-medium text-[var(--text)]">Recent scans</span>
          <span className="text-xs text-[var(--text-secondary)]">{scans.length} recorded</span>
        </div>

        {scans.length === 0 ? (
          <EmptyState
            title="No scan history"
            hint="Run a scan or import an assessment report to populate records."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-[var(--border)] bg-[var(--surface-2)] text-[var(--text-secondary)]">
                <tr>
                  <th className="py-2 px-3 font-normal">Status</th>
                  <th className="py-2 px-3 font-normal">Name</th>
                  <th className="py-2 px-3 font-normal">Engine</th>
                  <th className="py-2 px-3 font-normal">Target</th>
                  <th className="py-2 px-3 font-normal text-right">Findings</th>
                  <th className="py-2 px-3 font-normal text-right">Progress</th>
                  <th className="py-2 px-3 font-normal text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border)]">
                {scans.map((s) => {
                  const live = progress[s.id];
                  return (
                    <tr key={s.id} className="hover:bg-[var(--surface-hover)] transition-colors">
                      <td className="py-2 px-3">
                        <StatusBadge status={s.status} />
                      </td>
                      <td className="py-2 px-3 font-medium text-[var(--text)]">
                        {s.name}
                      </td>
                      <td className="py-2 px-3 font-mono-data text-[var(--text-secondary)] uppercase">
                        {s.scanner_type}
                      </td>
                      <td className="py-2 px-3 font-mono-data text-[var(--text-secondary)]">
                        {s.target}
                      </td>
                      <td className="py-2 px-3 text-right font-mono-data font-medium text-[var(--text)]">
                        {live && live.findings_count !== undefined && live.findings_count > 0 ? (
                          <span className="text-[var(--accent)] font-semibold">
                            {live.findings_count}
                          </span>
                        ) : (
                          s.findings_count
                        )}
                      </td>
                      <td className="py-2 px-3 text-right">
                        {(s.status === "pending" || s.status === "running") && live ? (
                          <div className="inline-flex items-center gap-2">
                            <span className="font-mono-data text-[11px] text-[var(--accent)]">{live.pct}%</span>
                            <div className="w-16 h-1 bg-[var(--surface-3)] rounded-full overflow-hidden">
                              <div
                                className="h-full bg-[var(--accent)]"
                                style={{ width: `${live.pct}%` }}
                              />
                            </div>
                          </div>
                        ) : (
                          <span
                            className="text-[var(--text-tertiary)] font-mono-data text-[11px]"
                            title={s.error_message || undefined}
                          >
                            {s.status === "completed"
                              ? "Done"
                              : s.status === "failed"
                              ? (s.error_message ? (s.error_message.length > 25 ? s.error_message.slice(0, 25) + "…" : s.error_message) : "Failed")
                              : live?.message || "Queued"}
                          </span>
                        )}
                      </td>
                      <td className="py-2 px-3 text-right">
                        {(s.status === "pending" || s.status === "running") && (
                          <button
                            type="button"
                            onClick={() => void stopScan(s.id)}
                            disabled={stopping[s.id]}
                            className="inline-flex items-center gap-1 rounded border border-[var(--critical)] px-2 py-1 text-[var(--critical)] disabled:opacity-50"
                            title="Stop scan"
                          >
                            <Square size={11} />
                            {stopping[s.id] ? "Stopping..." : "Stop"}
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function ImportForm({ onImport }: { onImport: (file: File, scannerType: string) => Promise<void> }) {
  const [scannerType, setScannerType] = useState("nmap");
  const [busy, setBusy] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const file = fileRef.current?.files?.[0];
    if (!file) return;
    setBusy(true);
    try {
      await onImport(file, scannerType);
      if (fileRef.current) fileRef.current.value = "";
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-3.5">
      <div>
        <label className="text-xs font-medium text-[var(--text)] block mb-1">
          Format
        </label>
        <Select
          value={scannerType}
          onChange={(e) => setScannerType(e.target.value)}
          className="w-full"
        >
          <option value="nmap">Nmap XML (.xml)</option>
          <option value="nessus">Tenable Nessus (.nessus)</option>
          <option value="openvas">OpenVAS GMP Report (.xml)</option>
          <option value="nuclei">Nuclei Findings (.jsonl)</option>
          <option value="import">Auto-detect from file structure</option>
        </Select>
      </div>

      <div className="border border-dashed border-[var(--border)] rounded-[5px] p-3 text-xs bg-[var(--surface-2)]">
        <input
          ref={fileRef}
          type="file"
          required
          className="w-full text-xs text-[var(--text-secondary)] file:mr-2 file:py-1 file:px-2.5 file:rounded-[4px] file:border file:border-[var(--border)] file:bg-[var(--surface)] file:text-[var(--text)] file:text-xs hover:file:bg-[var(--surface-hover)] cursor-pointer"
        />
      </div>

      <div className="pt-2">
        <Button
          type="submit"
          disabled={busy}
          variant="secondary"
          className="w-full"
          icon={FileUp}
        >
          {busy ? "Ingesting report..." : "Import report"}
        </Button>
      </div>
    </form>
  );
}
