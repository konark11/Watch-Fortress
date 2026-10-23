import { useEffect, useState } from "react";
import { Download, FlaskConical, Play } from "lucide-react";
import { api, downloadFile } from "../../frontend/src/api/client";
import { Button, Card } from "../../frontend/src/components/ui";

type Payload = {
  validation?: { valid?: boolean; errors?: string[]; warnings?: string[]; provenance?: string };
  dataset?: { findings_count?: number; candidate_pairs_count?: number; findings_path?: string; candidate_pairs_path?: string };
  metrics?: {
    provenance?: string;
    test_pairs?: number;
    label_distribution?: Record<string, number>;
    warnings?: string[];
    methods?: Record<string, {
      status: string; reason?: string; metrics?: Record<string, unknown>;
      confidence_intervals_95?: Record<string, [number, number]>;
      mean_latency_ms?: number; errors?: { pair_id: string; expected: string; predicted: string; finding_a: string; finding_b: string }[];
    }>;
  };
};
type FindingDetails = { scanner?: string; asset_id?: string; ip?: string; port?: string; service?: string; cve?: string; title?: string; severity?: string; description?: string };
type Candidate = { pair_id: string; finding_a: string; finding_b: string; finding_a_details?: FindingDetails; finding_b_details?: FindingDetails; label: string; split: string; provenance: string };

const EXPORTS = ["results.csv", "metrics.json", "run_manifest.json"];

export default function ExperimentsPage() {
  const [payload, setPayload] = useState<Payload>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [candidates, setCandidates] = useState<Candidate[]>([]);
  async function refresh() {
    try { setPayload(await api.get<Payload>("/research-lab/status")); } catch (err) { setError(err instanceof Error ? err.message : "Unable to load experiment status"); }
  }
  useEffect(() => { void refresh(); }, []);
  useEffect(() => { api.get<{ candidates: Candidate[] }>("/research-lab/dataset/candidates").then((result) => setCandidates(result.candidates)).catch(() => undefined); }, []);
  async function runExperiment() {
    setBusy(true); setError("");
    try { setPayload(await api.post<Payload>("/research-lab/run")); } catch (err) { setError(err instanceof Error ? err.message : "Experiment failed"); } finally { setBusy(false); }
  }
  async function syncDataset() {
    try { const result = await api.post<{ dataset: Payload["dataset"] }>("/research-lab/sync-dataset"); setPayload((current) => ({ ...current, dataset: result.dataset })); const next = await api.get<{ candidates: Candidate[] }>("/research-lab/dataset/candidates"); setCandidates(next.candidates); } catch (err) { setError(err instanceof Error ? err.message : "Unable to sync scan findings"); }
  }
  async function saveLabels() {
    try { await api.post("/research-lab/dataset/labels", { pairs: candidates }); setError(""); } catch (err) { setError(err instanceof Error ? err.message : "Unable to save labels"); }
  }
  function updateCandidate(index: number, key: "label" | "split", value: string) {
    setCandidates((current) => current.map((candidate, candidateIndex) => candidateIndex === index ? { ...candidate, [key]: value } : candidate));
  }
  const validation = payload.validation;
  const metrics = payload.metrics;
  const methods = metrics?.methods ?? {};
  return <div className="space-y-5">
    <div className="flex items-start justify-between gap-4">
      <div><h1 className="text-xl font-bold flex items-center gap-2"><FlaskConical size={18} className="text-[var(--brand)]" /> Research Lab</h1><p className="text-sm text-[var(--text-muted)] mt-1">Controlled finding-correlation comparison. Results are read from the last actual run.</p></div>
      <Button onClick={runExperiment} disabled={busy}><Play size={14} /> {busy ? "Running..." : "Run comparison"}</Button>
    </div>
    {(validation?.provenance === "SYNTHETIC_OR_MIXED" || metrics?.provenance === "SYNTHETIC_OR_MIXED") && <div className="border border-amber-500/40 bg-amber-500/10 text-amber-200 rounded-lg px-4 py-3 text-sm font-semibold">SYNTHETIC / MIXED PROVENANCE — do not present these results as real-scan evidence.</div>}
    {error && <Card className="text-[var(--critical)] text-sm">{error}</Card>}
    <Card><div className="flex items-center justify-between gap-4"><div><h2 className="font-semibold">Scan dataset</h2><p className="text-sm text-[var(--text-muted)] mt-1">{payload.dataset?.findings_count ?? 0} findings · {payload.dataset?.candidate_pairs_count ?? 0} candidate pairs</p><p className="text-xs text-[var(--text-dim)] mt-1">Findings are synchronized from SQLite after each completed/imported scan. Candidate labels are intentionally blank for review.</p></div><Button onClick={syncDataset}>Sync SQLite findings</Button></div></Card>
    {!!candidates.length && <Card><div className="flex items-center justify-between mb-3"><div><h2 className="font-semibold">Review candidate pairs</h2><p className="text-xs text-[var(--text-muted)] mt-1">Same asset and port. Compare the key fields, then assign a label and split.</p></div><Button onClick={saveLabels}>Save labels</Button></div><div className="space-y-2">{candidates.map((candidate, index) => <div key={candidate.pair_id} className="border border-[var(--border)] rounded-lg p-3"><div className="flex flex-wrap items-center justify-between gap-2 text-xs mb-2"><b>{candidate.pair_id}</b><div className="flex gap-2"><select aria-label={`${candidate.pair_id} label`} value={candidate.label} onChange={(event) => updateCandidate(index, "label", event.target.value)} className="bg-[var(--surface-2)] border border-[var(--border)] rounded px-2 py-1"><option value="">Label</option><option>SAME</option><option>RELATED</option><option>DIFFERENT</option></select><select aria-label={`${candidate.pair_id} split`} value={candidate.split} onChange={(event) => updateCandidate(index, "split", event.target.value)} className="bg-[var(--surface-2)] border border-[var(--border)] rounded px-2 py-1"><option value="">Split</option><option>train</option><option>test</option></select></div></div><div className="grid md:grid-cols-2 gap-2 text-xs"><FindingCard label={`Finding A · ${candidate.finding_a}`} details={candidate.finding_a_details} /><FindingCard label={`Finding B · ${candidate.finding_b}`} details={candidate.finding_b_details} /></div></div>)}</div></Card>}
    <Card><h2 className="font-semibold mb-2">Data validation</h2><div className="text-sm">{validation?.valid ? "VALID" : "NOT READY — methods will not run until validation passes."}</div>
      {!!validation?.errors?.length && <ul className="mt-2 list-disc pl-5 text-sm text-[var(--critical)]">{validation.errors.map((item) => <li key={item}>{item}</li>)}</ul>}
      {!!validation?.warnings?.length && <details className="mt-2 text-sm"><summary>{validation.warnings.length} warnings</summary><ul className="list-disc pl-5 mt-1">{validation.warnings.map((item) => <li key={item}>{item}</li>)}</ul></details>}
    </Card>
    {metrics && Object.keys(methods).length > 0 && <Card><div className="flex justify-between items-center mb-3"><h2 className="font-semibold">Method status and metrics</h2><span className="text-xs text-[var(--text-muted)]">{metrics.test_pairs ?? 0} test pairs · {Object.entries(metrics.label_distribution ?? {}).map(([key, value]) => `${key}: ${value}`).join(" · ")}</span></div>
      {!!metrics.warnings?.length && <div className="mb-3 text-xs text-amber-200">{metrics.warnings.join(" · ")}</div>}
      <div className="overflow-x-auto"><table className="w-full text-sm"><thead><tr className="text-left text-[var(--text-muted)]"><th className="py-2">Method</th><th>Status</th><th>Precision / Recall / F1 (SAME)</th><th>Macro-F1</th><th>Mean latency</th></tr></thead><tbody>{Object.entries(methods).map(([name, method]) => <tr key={name} className="border-t border-[var(--border)]"><td className="py-2">{name}</td><td>{method.status}{method.reason ? ` — ${method.reason}` : ""}</td><td>{method.metrics ? `${Number(method.metrics.precision_same).toFixed(3)} / ${Number(method.metrics.recall_same).toFixed(3)} / ${Number(method.metrics.f1_same).toFixed(3)}` : "—"}</td><td>{method.metrics ? Number(method.metrics.macro_f1).toFixed(3) : "—"}</td><td>{method.mean_latency_ms != null ? `${method.mean_latency_ms.toFixed(2)} ms` : "—"}</td></tr>)}</tbody></table></div>
      <details className="mt-3 text-xs"><summary>Confusion matrices</summary><div className="mt-2 space-y-1">{Object.entries(methods).map(([name, method]) => <div key={`${name}-matrix`}><b>{name}</b>: {method.metrics?.confusion_matrix ? JSON.stringify(method.metrics.confusion_matrix) : "NOT RUN"}</div>)}</div></details>
    </Card>}
    <Card><h2 className="font-semibold mb-3">Exports</h2><div className="flex flex-wrap gap-2">{EXPORTS.map((name) => <button key={name} onClick={() => void downloadFile(`/research-lab/export/${name}`, name)} className="inline-flex items-center gap-2 rounded-lg border border-[var(--border)] px-3 py-2 text-sm hover:bg-[var(--surface-2)]"><Download size={14} /> {name}</button>)}</div></Card>
    {Object.entries(methods).map(([name, method]) => method.errors?.length ? <Card key={`${name}-errors`}><h2 className="font-semibold mb-2">{name} errors ({method.errors.length})</h2><div className="space-y-2 text-sm">{method.errors.map((item) => <div key={item.pair_id} className="border-t border-[var(--border)] pt-2"><b>{item.pair_id}</b>: expected {item.expected}, predicted {item.predicted}<div className="text-xs text-[var(--text-muted)]">{item.finding_a} · {item.finding_b}</div></div>)}</div></Card> : null)}
  </div>;
}

function FindingCard({ label, details }: { label: string; details?: FindingDetails }) {
  if (!details) return <div className="bg-[var(--surface-2)] rounded p-2 text-[var(--text-muted)]">{label}<div className="mt-1">Details unavailable; sync the dataset again.</div></div>;
  return <div className="bg-[var(--surface-2)] rounded p-2 min-w-0"><div className="font-semibold text-[var(--brand)] mb-1 truncate">{label}</div><div className="grid grid-cols-2 gap-x-3 gap-y-1"><span>Scanner <b>{details.scanner || "—"}</b></span><span>Severity <b>{details.severity || "—"}</b></span><span>Asset <b>{details.asset_id || "—"}</b></span><span>IP <b>{details.ip || "—"}</b></span><span>Port <b>{details.port || "—"}</b></span><span>Service <b>{details.service || "—"}</b></span><span className="col-span-2 truncate">CVE <b>{details.cve || "—"}</b></span></div><details className="mt-2"><summary className="cursor-pointer text-[var(--text-muted)]">Title and description</summary><div className="mt-1"><div><b>{details.title || "—"}</b></div><div className="mt-1 text-[var(--text-muted)] max-h-20 overflow-y-auto">{details.description || "No description"}</div></div></details></div>;
}
