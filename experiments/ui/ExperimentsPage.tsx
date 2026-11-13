import { useEffect, useState } from "react";
import { Download, FlaskConical, Play, RefreshCw, Save, AlertTriangle } from "lucide-react";
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
type RagRun = { run_id: string; status: string; split?: string; rows?: number };

const EXPORTS = ["results.csv", "metrics.json", "run_manifest.json"];

export default function ExperimentsPage() {
  const [payload, setPayload] = useState<Payload>({});
  const [busy, setBusy] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [candidates, setCandidates] = useState<Candidate[]>([]);
  const [ragRuns, setRagRuns] = useState<RagRun[]>([]);

  async function refresh() {
    try {
      const result = await api.get<Payload>("/research-lab/status");
      setPayload(result && typeof result === "object" ? result : {});
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load experiment status");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  useEffect(() => {
    api.get<{ runs: RagRun[] }>("/observability/evaluations")
      .then((result) => setRagRuns(Array.isArray(result?.runs) ? result.runs : []))
      .catch((err: Error) => {
        console.warn("Failed to load evaluation runs:", err);
        setError((current) => current || "Evaluation metadata is unavailable.");
      });
  }, []);

  useEffect(() => {
    api
      .get<{ candidates: Candidate[] }>("/research-lab/dataset/candidates")
      .then((result) => setCandidates(Array.isArray(result?.candidates) ? result.candidates : []))
      .catch((err: Error) => {
        console.warn("Failed to load research candidates:", err);
        setError((current) => current || "Research candidates are unavailable.");
      });
  }, []);

  async function runExperiment() {
    setBusy(true);
    setError("");
    try {
      const next = await api.post<Payload>("/research-lab/run");
      setPayload(next && typeof next === "object" ? next : {});
    } catch (err) {
      setError(err instanceof Error ? err.message : "Experiment run failed");
    } finally {
      setBusy(false);
    }
  }

  async function syncDataset() {
    setSyncing(true);
    try {
      const result = await api.post<{ dataset: Payload["dataset"] }>("/research-lab/sync-dataset");
      setPayload((current) => ({ ...current, dataset: result.dataset }));
      const next = await api.get<{ candidates: Candidate[] }>("/research-lab/dataset/candidates");
      setCandidates(Array.isArray(next?.candidates) ? next.candidates : []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to sync scan findings");
    } finally {
      setSyncing(false);
    }
  }

  async function saveLabels() {
    setSaving(true);
    try {
      await api.post("/research-lab/dataset/labels", { pairs: candidates });
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to save labels");
    } finally {
      setSaving(false);
    }
  }

  function updateCandidate(index: number, key: "label" | "split", value: string) {
    setCandidates((current) =>
      current.map((candidate, candidateIndex) =>
        candidateIndex === index ? { ...candidate, [key]: value } : candidate,
      ),
    );
  }

  const validation = payload.validation;
  const metrics = payload.metrics;
  const methods = metrics?.methods ?? {};

  return (
    <div className="space-y-6">
      {/* Title & Run Action */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--text)] flex items-center gap-2">
            <FlaskConical size={18} className="text-[var(--brand)]" />
            Empirical Research Lab
          </h1>
          <p className="text-xs text-[var(--text-muted)] mt-1">
            Controlled benchmarking of finding-correlation algorithms and cross-scanner deduplication metrics
          </p>
        </div>
        <Button onClick={runExperiment} disabled={busy} variant="primary" size="sm" icon={Play}>
          {busy ? "Evaluating Benchmarks..." : "Run Method Comparison"}
        </Button>
      </div>

      {loading && <div className="text-xs text-[var(--text-muted)]">Loading research lab data...</div>}
      {(validation?.provenance === "SYNTHETIC_OR_MIXED" || metrics?.provenance === "SYNTHETIC_OR_MIXED") && (
        <div className="border border-amber-500/40 bg-amber-500/10 text-amber-200 rounded-xl px-4 py-3 text-xs font-mono-data font-semibold flex items-center gap-2">
          <AlertTriangle size={16} className="text-amber-400 shrink-0" />
          <span>SYNTHETIC / MIXED PROVENANCE — Controlled test dataset detected; do not report as live scan telemetry.</span>
        </div>
      )}

      {error && (
        <Card className="text-[var(--critical)] text-xs font-mono-data border-[rgba(251,63,94,0.3)] bg-[var(--critical-dim)]">
          {error}
        </Card>
      )}

      <Card header="Assistant RAG evaluation" subtitle="Separate reviewed retrieval runs; NOT RUN means no measured result">
        {ragRuns.length === 0 ? (
          <div className="text-xs text-[var(--text-muted)]">NOT RUN</div>
        ) : (
          <div className="space-y-1">
            {ragRuns.map((run) => (
              <div key={run.run_id} className="flex items-center justify-between border-b border-[var(--border)] py-2 text-xs font-mono-data">
                <span>{run.run_id}</span>
                <span>{run.status} · {run.split || "unavailable"} · {run.rows ?? "?"} rows</span>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Dataset Sync Card */}
      <Card
        header="Findings Benchmark Dataset"
        subtitle="Synchronized candidate pairs from all imported and live scanner runs"
        action={
          <Button onClick={syncDataset} disabled={syncing} variant="secondary" size="sm" icon={RefreshCw}>
            {syncing ? "Syncing..." : "Sync SQLite Findings"}
          </Button>
        }
      >
        <div className="flex items-center gap-6 font-mono-data text-xs">
          <div>
            <span className="text-[var(--text-dim)] uppercase block text-[10px]">Total Findings</span>
            <span className="text-lg font-bold text-[var(--text)]">{payload.dataset?.findings_count ?? 0}</span>
          </div>
          <div>
            <span className="text-[var(--text-dim)] uppercase block text-[10px]">Candidate Pairs</span>
            <span className="text-lg font-bold text-[var(--brand)]">{payload.dataset?.candidate_pairs_count ?? 0}</span>
          </div>
        </div>
      </Card>

      {/* Candidate Pair Labeling Section */}
      {!!candidates.length && (
        <Card
          header={`Candidate Correlation Pairs (${candidates.length})`}
          subtitle="Review pairs sharing host & port coordinates to assign truth labels"
          action={
            <Button onClick={saveLabels} disabled={saving} variant="primary" size="sm" icon={Save}>
              {saving ? "Saving..." : "Save Truth Labels"}
            </Button>
          }
        >
          <div className="space-y-3 max-h-[500px] overflow-y-auto pr-1">
            {candidates.map((candidate, index) => (
              <div
                key={candidate.pair_id}
                className="border border-[var(--border)] bg-[var(--surface-2)]/40 rounded-xl p-3.5 space-y-2.5"
              >
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono-data">
                  <span className="font-bold text-[var(--brand)]">{candidate.pair_id}</span>
                  <div className="flex gap-2">
                    <select
                      aria-label={`${candidate.pair_id} label`}
                      value={candidate.label}
                      onChange={(e) => updateCandidate(index, "label", e.target.value)}
                      className="bg-[var(--surface-3)] border border-[var(--border)] rounded-md px-2 py-1 text-xs text-[var(--text)] font-mono-data cursor-pointer"
                    >
                      <option value="">Select Label</option>
                      <option value="SAME">SAME</option>
                      <option value="RELATED">RELATED</option>
                      <option value="DIFFERENT">DIFFERENT</option>
                    </select>
                    <select
                      aria-label={`${candidate.pair_id} split`}
                      value={candidate.split}
                      onChange={(e) => updateCandidate(index, "split", e.target.value)}
                      className="bg-[var(--surface-3)] border border-[var(--border)] rounded-md px-2 py-1 text-xs text-[var(--text)] font-mono-data cursor-pointer"
                    >
                      <option value="">Select Split</option>
                      <option value="train">train</option>
                      <option value="test">test</option>
                    </select>
                  </div>
                </div>

                <div className="grid md:grid-cols-2 gap-3 text-xs">
                  <FindingCard label={`Finding A · ${candidate.finding_a}`} details={candidate.finding_a_details} />
                  <FindingCard label={`Finding B · ${candidate.finding_b}`} details={candidate.finding_b_details} />
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Validation Card */}
      <Card header="Dataset Integrity Validation" subtitle="Checks for balance, split isolation, and null values">
        <div className="flex items-center gap-2 text-xs font-mono-data">
          <span
            className={`w-2 h-2 rounded-full ${
              validation?.valid ? "bg-[var(--brand)]" : "bg-[var(--critical)]"
            }`}
          />
          <span className="font-bold text-[var(--text)]">
            {validation?.valid
              ? "DATASET READY — All validation criteria satisfied"
              : "PENDING VALIDATION — Complete labels to activate comparison benchmarks"}
          </span>
        </div>
        {!!validation?.errors?.length && (
          <ul className="mt-2.5 list-disc pl-5 text-xs text-[var(--critical)] font-mono-data space-y-1">
            {validation.errors.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        )}
      </Card>

      {/* Method Status and Metrics Table */}
      {metrics && Object.keys(methods).length > 0 && (
        <Card
          header="Model Performance &amp; Evaluation Metrics"
          subtitle={`${metrics.test_pairs ?? 0} test pairs · ${Object.entries(metrics.label_distribution ?? {})
            .map(([k, v]) => `${k}: ${v}`)
            .join(" · ")}`}
        >
          <div className="overflow-x-auto">
            <table className="w-full text-xs font-mono-data">
              <thead>
                <tr className="border-b border-[var(--border)] text-[var(--text-dim)] uppercase">
                  <th className="text-left py-2.5 px-3">Method Algorithm</th>
                  <th className="text-left py-2.5 px-3">State</th>
                  <th className="text-left py-2.5 px-3">P / R / F1 (SAME)</th>
                  <th className="text-left py-2.5 px-3">Macro-F1</th>
                  <th className="text-right py-2.5 px-3">Mean Latency</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border-soft)]">
                {Object.entries(methods).map(([name, method]) => (
                  <tr key={name} className="hover:bg-[var(--surface-2)]/30">
                    <td className="py-2.5 px-3 font-bold text-[var(--text)]">{name}</td>
                    <td className="py-2.5 px-3 text-[var(--text-muted)]">
                      {method.status}
                      {method.reason ? ` — ${method.reason}` : ""}
                    </td>
                    <td className="py-2.5 px-3 text-[var(--brand)]">
                      {method.metrics
                        ? `${Number(method.metrics.precision_same).toFixed(3)} / ${Number(
                            method.metrics.recall_same,
                          ).toFixed(3)} / ${Number(method.metrics.f1_same).toFixed(3)}`
                        : "—"}
                    </td>
                    <td className="py-2.5 px-3 font-semibold text-[var(--text)]">
                      {method.metrics ? Number(method.metrics.macro_f1).toFixed(3) : "—"}
                    </td>
                    <td className="py-2.5 px-3 text-right text-[var(--text-dim)]">
                      {method.mean_latency_ms != null ? `${method.mean_latency_ms.toFixed(2)} ms` : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* Exports Card */}
      <Card header="Export Benchmark Artifacts" subtitle="Download reproducible run manifest and raw evaluation metrics">
        <div className="flex flex-wrap gap-2.5">
          {EXPORTS.map((name) => (
            <button
              key={name}
              onClick={() => void downloadFile(`/research-lab/export/${name}`, name)}
              className="inline-flex items-center gap-2 rounded-lg border border-[var(--border)] px-3.5 py-2 text-xs font-mono-data text-[var(--text)] bg-[var(--surface-2)] hover:border-[var(--brand)] hover:text-[var(--brand)] transition-colors cursor-pointer"
            >
              <Download size={13} /> {name}
            </button>
          ))}
        </div>
      </Card>
    </div>
  );
}

function FindingCard({ label, details }: { label: string; details?: FindingDetails }) {
  if (!details) {
    return (
      <div className="bg-[var(--surface-2)] border border-[var(--border)] rounded-xl p-3 text-xs text-[var(--text-muted)] font-mono-data">
        {label}
        <div className="text-[10px] text-[var(--text-dim)] mt-1">Details pending sync.</div>
      </div>
    );
  }
  return (
    <div className="bg-[var(--surface-2)] border border-[var(--border)] rounded-xl p-3 text-xs font-mono-data">
      <div className="font-bold text-[var(--brand)] mb-2 truncate">{label}</div>
      <div className="grid grid-cols-2 gap-x-2 gap-y-1 text-[11px] text-[var(--text-muted)]">
        <span>Engine: <b className="text-[var(--text)]">{details.scanner || "—"}</b></span>
        <span>Severity: <b className="text-[var(--text)]">{details.severity || "—"}</b></span>
        <span>Asset IP: <b className="text-[var(--text)]">{details.ip || "—"}</b></span>
        <span>Port: <b className="text-[var(--text)]">{details.port || "—"}</b></span>
        <span className="col-span-2 truncate">CVE: <b className="text-[var(--text)]">{details.cve || "—"}</b></span>
      </div>
    </div>
  );
}
