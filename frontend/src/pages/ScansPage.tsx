import { useEffect, useRef, useState } from "react";
import { Play, Upload, CircleCheck, CircleX, Loader2 } from "lucide-react";
import { api } from "../api/client";
import type { Scan } from "../types";
import { Card, Button, Input, Select, EmptyState } from "../components/ui";

const SCANNERS = [
  { value: "nmap", label: "Nmap" },
  { value: "openvas", label: "OpenVAS" },
  { value: "nessus", label: "Nessus" },
  { value: "nuclei", label: "Nuclei" },
  { value: "custom", label: "Custom Script" },
];

const NMAP_PROFILES = [
  { value: "quick", label: "Quick (top ports, no vuln detection)" },
  { value: "service_version", label: "Service/version detection (no vuln detection)" },
  { value: "os_detection", label: "OS detection (no vuln detection)" },
  { value: "full", label: "Full port scan (no vuln detection)" },
  { value: "all_ports", label: "All 65,535 ports (no service detection)" },
  { value: "all_ports_service_version", label: "All 65,535 ports + service/version detection" },
  { value: "vuln_scripts", label: "Vulnerability scripts (NSE vulners + ssl-cert) — finds CVEs" },
];

const NUCLEI_SEVERITY_PROFILES = [
  { value: "standard", label: "Standard (low/medium/high/critical)" },
  { value: "critical_high", label: "Critical + High only" },
  { value: "all", label: "All (incl. info)" },
];

export default function ScansPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [availability, setAvailability] = useState<Record<string, boolean>>({});
  const [selectedScanners, setSelectedScanners] = useState<string[]>(["nmap"]);
  const [target, setTarget] = useState("");
  const [name, setName] = useState("");
  const [nmapProfile, setNmapProfile] = useState("vuln_scripts");
  const [nucleiSeverity, setNucleiSeverity] = useState("standard");
  const [nucleiTags, setNucleiTags] = useState("");
  const [launching, setLaunching] = useState(false);
  const [progress, setProgress] = useState<Record<number, { pct: number; message: string }>>({});
  const wsRefs = useRef<Record<number, WebSocket>>({});

  useEffect(() => {
    load();
    api.get<Record<string, boolean>>("/scans/scanner-availability").then(setAvailability);
    const interval = setInterval(load, 6000);
    return () => clearInterval(interval);
  }, []);

  function load() {
    api.get<{ scans: Scan[] }>("/scans").then((r) => {
      setScans(r.scans);
      r.scans
        .filter((s) => s.status === "running" && !wsRefs.current[s.id])
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

  async function launch(e: React.FormEvent) {
    e.preventDefault();
    if (selectedScanners.length === 0) {
      alert("Select at least one scanner");
      return;
    }
    setLaunching(true);
    try {
      const results = await Promise.allSettled(
        selectedScanners.map(async (scannerType) => {
          const options: Record<string, unknown> =
            scannerType === "nmap"
              ? { profile: nmapProfile }
              : scannerType === "nuclei"
              ? { severity_profile: nucleiSeverity, ...(nucleiTags ? { tags: nucleiTags } : {}) }
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
      const failed = results.filter((result): result is PromiseRejectedResult => result.status === "rejected");
      if (failed.length > 0) {
        alert(`${failed.length} scanner${failed.length === 1 ? "" : "s"} failed to launch. Other selected scanners are running.`);
      }
      setTarget("");
      setName("");
      load();
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
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold">Scan Orchestration</h1>
        <p className="text-sm text-[var(--text-muted)] mt-1">Launch scanners directly or import results from a file</p>
      </div>

      <div className="grid grid-cols-2 gap-6">
        <Card>
          <h3 className="text-xs uppercase tracking-wide text-[var(--text-muted)] mb-4">Launch a Scan</h3>
          <form onSubmit={launch} className="space-y-3">
            <div>
              <label className="text-xs text-[var(--text-muted)] block mb-1">Scanners (run in parallel)</label>
              <div className="grid grid-cols-2 gap-2 rounded-lg border border-[var(--border)] p-3">
                {SCANNERS.map((s) => (
                  <label key={s.value} className="flex items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={selectedScanners.includes(s.value)}
                      onChange={(e) => {
                        setSelectedScanners((current) =>
                          e.target.checked
                            ? [...current, s.value]
                            : current.filter((value) => value !== s.value),
                        );
                      }}
                    />
                    <span>{s.label}</span>
                    {availability[s.value] === false && <span className="text-xs text-[var(--text-dim)]">(unavailable)</span>}
                  </label>
                ))}
              </div>
              <div className="text-xs text-[var(--text-dim)] mt-1">
                Each scanner gets its own scan record and its output is ingested as soon as that scanner completes.
              </div>
            </div>
            <div>
              <label className="text-xs text-[var(--text-muted)] block mb-1">Target (IP, hostname, or CIDR)</label>
              <Input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="10.0.0.0/24 or scanme.nmap.org" required className="w-full" />
            </div>
            <div>
              <label className="text-xs text-[var(--text-muted)] block mb-1">Scan name (optional)</label>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Weekly perimeter scan" className="w-full" />
            </div>
            {selectedScanners.includes("nmap") && (
              <div>
                <label className="text-xs text-[var(--text-muted)] block mb-1">Scan profile</label>
                <Select value={nmapProfile} onChange={(e) => setNmapProfile(e.target.value)} className="w-full">
                  {NMAP_PROFILES.map((p) => (
                    <option key={p.value} value={p.value}>{p.label}</option>
                  ))}
                </Select>
                {nmapProfile !== "vuln_scripts" && (
                  <div className="text-xs text-[var(--text-dim)] mt-1">
                    This profile discovers hosts/ports/services only — it won't produce vulnerability
                    findings. Pick "Vulnerability scripts" to have Nmap run NSE vuln-detection scripts.
                  </div>
                )}
                {(nmapProfile === "all_ports" || nmapProfile === "all_ports_service_version") && (
                  <div className="text-xs text-[var(--medium)] mt-1">
                    This scans all 65,535 TCP ports and may take significantly longer than a top-ports scan.
                  </div>
                )}
                {nmapProfile === "vuln_scripts" && (
                  <div className="text-xs text-[var(--text-dim)] mt-1">
                    Requires the nmap "vulners" NSE script and internet access to vulners.com for CVE
                    lookups. On an air-gapped deployment this script will run but may find nothing —
                    import a Nessus/OpenVAS/Nuclei report instead for offline vulnerability detection.
                  </div>
                )}
              </div>
            )}
            {selectedScanners.includes("nuclei") && (
              <div className="space-y-2">
                <div>
                  <label className="text-xs text-[var(--text-muted)] block mb-1">Severity</label>
                  <Select value={nucleiSeverity} onChange={(e) => setNucleiSeverity(e.target.value)} className="w-full">
                    {NUCLEI_SEVERITY_PROFILES.map((p) => (
                      <option key={p.value} value={p.value}>{p.label}</option>
                    ))}
                  </Select>
                </div>
                <div>
                  <label className="text-xs text-[var(--text-muted)] block mb-1">Template tags (optional)</label>
                  <Input value={nucleiTags} onChange={(e) => setNucleiTags(e.target.value)} placeholder="cve,exposure" className="w-full" />
                </div>
              </div>
            )}
            {selectedScanners.some((scanner) => availability[scanner] === false) && (
              <div className="text-xs text-[var(--medium)] bg-[var(--medium-dim)] rounded-lg px-3 py-2">
                One or more selected scanners are not currently configured/reachable. They will fail with a clear error; configured scanners will still run.
              </div>
            )}
            <Button type="submit" disabled={launching || selectedScanners.length === 0} className="w-full flex items-center justify-center gap-2">
              <Play size={14} /> {launching ? "Launching scanners..." : `Launch ${selectedScanners.length || ""} scanner${selectedScanners.length === 1 ? "" : "s"}`}
            </Button>
          </form>
        </Card>

        <Card>
          <h3 className="text-xs uppercase tracking-wide text-[var(--text-muted)] mb-4">Import Scan Results</h3>
          <p className="text-xs text-[var(--text-dim)] mb-3">Nmap XML · Nessus .nessus · OpenVAS XML · Nuclei JSON/JSONL · CSV · JSON</p>
          <ImportForm onImport={handleImport} />
        </Card>
      </div>

      <Card>
        <h3 className="text-xs uppercase tracking-wide text-[var(--text-muted)] mb-4">Scan History</h3>
        {scans.length === 0 ? (
          <EmptyState title="No scans yet" hint="Launch a scan or import a report to get started." />
        ) : (
          <div className="space-y-2">
            {scans.map((s) => {
              const live = progress[s.id];
              return (
                <div key={s.id} className="flex items-center justify-between py-2.5 border-b border-[var(--border-soft)] last:border-0">
                  <div className="flex items-center gap-3 min-w-0">
                    <StatusIcon status={s.status} />
                    <div className="min-w-0">
                      <div className="text-sm font-medium truncate">{s.name}</div>
                      <div className="text-xs text-[var(--text-dim)] font-mono-data">
                        {s.scanner_type} → {s.target}
                        {s.error_message && <span className="text-[var(--critical)]"> · {s.error_message}</span>}
                      </div>
                    </div>
                  </div>
                  <div className="text-right shrink-0 ml-4">
                    {s.status === "running" && live ? (
                      <div className="w-40">
                        <div className="h-1.5 rounded-full bg-[var(--surface-2)] overflow-hidden mb-1">
                          <div className="h-full bg-[var(--brand)] rounded-full transition-all" style={{ width: `${live.pct}%` }} />
                        </div>
                        <div className="text-[10px] text-[var(--text-dim)] truncate">{live.message}</div>
                      </div>
                    ) : (
                      <span className="text-xs text-[var(--text-muted)]">{s.findings_count} findings</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </Card>
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
    <form onSubmit={handleSubmit} className="space-y-3">
      <Select value={scannerType} onChange={(e) => setScannerType(e.target.value)} className="w-full">
        {SCANNERS.map((s) => (
          <option key={s.value} value={s.value}>{s.label}</option>
        ))}
        <option value="import">Auto-detect format</option>
      </Select>
      <input ref={fileRef} type="file" required className="w-full text-sm text-[var(--text-muted)] file:mr-3 file:py-2 file:px-3 file:rounded-lg file:border-0 file:bg-[var(--surface-3)] file:text-[var(--text)] file:text-sm" />
      <Button type="submit" disabled={busy} variant="secondary" className="w-full flex items-center justify-center gap-2">
        <Upload size={14} /> {busy ? "Importing..." : "Import & Analyze"}
      </Button>
    </form>
  );
}

function StatusIcon({ status }: { status: string }) {
  if (status === "completed") return <CircleCheck size={18} className="text-[var(--brand)] shrink-0" />;
  if (status === "failed") return <CircleX size={18} className="text-[var(--critical)] shrink-0" />;
  if (status === "running") return <Loader2 size={18} className="text-[var(--low)] animate-spin shrink-0" />;
  return <div className="w-[18px] h-[18px] rounded-full bg-[var(--surface-3)] shrink-0" />;
}
