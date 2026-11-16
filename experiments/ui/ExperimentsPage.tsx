import { useEffect, useState, useMemo } from "react";
import {
  Download,
  FlaskConical,
  Play,
  RefreshCw,
  Save,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  Coins,
  ChevronDown,
  ChevronRight,
  Sparkles,
  Database,
  Layers,
  Cpu,
} from "lucide-react";
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
type RagRun = {
  run_id: string;
  status: string;
  purpose?: string;
  split?: string;
  rows?: number;
  backend?: string;
  index_state?: string;
  failures?: number;
  reranker_fallback_count?: number;
  timestamp?: string;
  metrics?: {
    retrieval?: { recall_at_5?: number; mrr?: number; ndcg_at_5?: number };
    latency_ms?: { p50?: number };
  };
};

export type BenchmarkQuestion = {
  question_id: string;
  question: string;
  gold_answer: string;
  product: string;
  target_cwe_class: string;
  difficulty: string;
  summary: string;
  confusers?: string[];
};

export type RetrievedEvidence = {
  id: string;
  title: string;
  score: number;
  source: string;
  snippet: string;
};

export type ComparisonArm = {
  id: string;
  name: string;
  description: string;
  hit: boolean;
  rank: number | null;
  retrieval_latency_ms: number;
  generation_latency_ms: number;
  latency_ms: number;
  retrieved_docs: RetrievedEvidence[];
  answer: string;
  input_tokens: number;
  output_tokens: number;
  total_tokens: number;
  estimated_cost_usd: number;
  actual_cost_usd: number;
  is_free_tier: boolean;
  model: string;
};

export type BenchmarkComparisonResult = {
  question: string;
  gold_cve: string | null;
  timestamp: string;
  arms: ComparisonArm[];
  metadata?: BenchmarkQuestion;
};

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

  // -------------------------------------------------------------
  // Interactive 3-Way RAG Empirical Benchmark State
  // -------------------------------------------------------------
  const [benchmarkQuestions, setBenchmarkQuestions] = useState<BenchmarkQuestion[]>([]);
  const [selectedQuestionId, setSelectedQuestionId] = useState<string>("");
  const [questionSearchFilter, setQuestionSearchFilter] = useState<string>("");
  const [activeQuestionText, setActiveQuestionText] = useState<string>("");
  const [topK, setTopK] = useState<number>(5);
  const [runningBenchmark, setRunningBenchmark] = useState(false);
  const [benchmarkError, setBenchmarkError] = useState("");
  const [activeComparison, setActiveComparison] = useState<BenchmarkComparisonResult | null>(null);
  const [sessionHistory, setSessionHistory] = useState<BenchmarkComparisonResult[]>([]);
  const [expandedDocsArm, setExpandedDocsArm] = useState<Record<string, boolean>>({
    hybrid_rag: true,
    hybrid_reranker: true,
    hybrid_jev_reranker: true,
  });

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
      });
  }, []);

  useEffect(() => {
    api
      .get<{ candidates: Candidate[] }>("/research-lab/dataset/candidates")
      .then((result) => setCandidates(Array.isArray(result?.candidates) ? result.candidates : []))
      .catch((err: Error) => {
        console.warn("Failed to load research candidates:", err);
      });
  }, []);

  // Load the 86 curated benchmark questions
  useEffect(() => {
    api
      .get<{ count: number; questions: BenchmarkQuestion[] }>("/research/benchmark-questions")
      .then((result) => {
        if (result && Array.isArray(result.questions) && result.questions.length > 0) {
          setBenchmarkQuestions(result.questions);
          setSelectedQuestionId(result.questions[0].question_id);
          setActiveQuestionText(result.questions[0].question);
        }
      })
      .catch((err: Error) => {
        console.warn("Failed to load benchmark questions:", err);
        setBenchmarkError("Benchmark questions failed to load from /api/research/benchmark-questions");
      });
  }, []);

  // Selected question metadata
  const selectedQuestionMeta = useMemo(() => {
    return benchmarkQuestions.find((q) => q.question_id === selectedQuestionId);
  }, [benchmarkQuestions, selectedQuestionId]);

  // Filtered benchmark questions for search dropdown
  const filteredQuestions = useMemo(() => {
    if (!questionSearchFilter.trim()) return benchmarkQuestions;
    const filter = questionSearchFilter.toLowerCase();
    return benchmarkQuestions.filter(
      (q) =>
        q.question_id.toLowerCase().includes(filter) ||
        q.product.toLowerCase().includes(filter) ||
        q.gold_answer.toLowerCase().includes(filter) ||
        q.question.toLowerCase().includes(filter) ||
        q.summary.toLowerCase().includes(filter),
    );
  }, [benchmarkQuestions, questionSearchFilter]);

  function handleSelectQuestion(qId: string) {
    setSelectedQuestionId(qId);
    const item = benchmarkQuestions.find((q) => q.question_id === qId);
    if (item) {
      setActiveQuestionText(item.question);
    }
  }

  async function runSingleComparison() {
    if (!activeQuestionText.trim()) return;
    setRunningBenchmark(true);
    setBenchmarkError("");

    try {
      const payloadBody = {
        question_id: selectedQuestionId || undefined,
        question: activeQuestionText,
        gold_cve: selectedQuestionMeta?.gold_answer,
        top_k: topK,
      };

      const result = await api.post<BenchmarkComparisonResult>("/research/benchmark-compare", payloadBody);
      setActiveComparison(result);
      setSessionHistory((prev) => [result, ...prev]);
    } catch (err) {
      setBenchmarkError(err instanceof Error ? err.message : "3-way comparison failed");
    } finally {
      setRunningBenchmark(false);
    }
  }

  function toggleArmDocs(armId: string) {
    setExpandedDocsArm((prev) => ({ ...prev, [armId]: !prev[armId] }));
  }

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

  function exportSessionRuns() {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(sessionHistory, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `rag_benchmark_session_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  }

  const validation = payload.validation;
  const metrics = payload.metrics;
  const methods = metrics?.methods ?? {};
  const featuredRun = [...ragRuns]
    .filter((run) => run.status === "RUN" && (run.purpose === "development" || run.split === "development"))
    .sort((a, b) => (b.timestamp || "").localeCompare(a.timestamp || ""))[0] || ragRuns[0];
  const featuredRetrieval = featuredRun?.metrics?.retrieval;
  const featuredLatency = featuredRun?.metrics?.latency_ms?.p50;

  return (
    <div className="space-y-6">
      {/* ------------------------------------------------------------- */}
      {/* Interactive 3-Way RAG Empirical Comparison (Top Showcase)    */}
      {/* ------------------------------------------------------------- */}
      <div className="rounded-xl border border-[var(--border-strong)] bg-gradient-to-b from-[var(--surface-2)]/90 to-[var(--surface)] p-5 shadow-sm space-y-4">
        {/* Header Bar */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-[var(--border)] pb-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-[var(--accent)]/15 text-[var(--accent)]">
                <Sparkles size={16} />
              </span>
              <h2 className="text-base font-bold text-[var(--text)] tracking-tight">
                Live 3-Way RAG Empirical Comparison
              </h2>
              <span className="rounded-full bg-[var(--accent)]/10 px-2.5 py-0.5 text-[10px] font-mono-data font-semibold text-[var(--accent)]">
                86 Hard Evaluation Benchmarks
              </span>
            </div>
            <p className="text-xs text-[var(--text-secondary)] mt-1">
              Select any benchmark question from the dropdown and hit Enter to observe head-to-head empirical metrics across three retrieval architectures.
            </p>
          </div>

          <div className="flex items-center gap-2 self-start md:self-auto">
            <span className="inline-flex items-center gap-1.5 rounded-md border border-[var(--border)] bg-[var(--surface-3)]/60 px-2.5 py-1 text-[11px] font-mono-data text-[var(--text-secondary)]">
              <Cpu size={12} className="text-emerald-400" />
              <span>Model: <b className="text-[var(--text)]">openai/gpt-oss-120b</b> (Free Tier)</span>
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-md border border-[var(--border)] bg-[var(--surface-3)]/60 px-2.5 py-1 text-[11px] font-mono-data text-[var(--text-secondary)]">
              <Database size={12} className="text-[var(--accent)]" />
              <span>Vectors: <b className="text-[var(--text)]">1,804 CVEs indexed</b></span>
            </span>
          </div>
        </div>

        {/* Question Selector Controls */}
        <div className="space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-12 gap-3 items-center">
            {/* Search Filter input */}
            <div className="md:col-span-4">
              <label className="block text-[10px] uppercase font-mono-data tracking-wider text-[var(--text-dim)] mb-1">
                Filter Benchmark Questions ({filteredQuestions.length}/86)
              </label>
              <input
                type="text"
                placeholder="Search by product, CVE (e.g. ActiveMQ, Log4j, CVE-2015-5254)..."
                value={questionSearchFilter}
                onChange={(e) => setQuestionSearchFilter(e.target.value)}
                className="w-full rounded-md border border-[var(--border)] bg-[var(--surface-3)] px-3 py-1.5 text-xs text-[var(--text)] placeholder:text-[var(--text-tertiary)] focus:border-[var(--accent)] focus:outline-none"
              />
            </div>

            {/* Dropdown Selector */}
            <div className="md:col-span-6">
              <label className="block text-[10px] uppercase font-mono-data tracking-wider text-[var(--text-dim)] mb-1">
                Target Benchmark Question
              </label>
              <select
                aria-label="Benchmark Question Selector"
                value={selectedQuestionId}
                onChange={(e) => handleSelectQuestion(e.target.value)}
                className="w-full rounded-md border border-[var(--border)] bg-[var(--surface-3)] px-3 py-1.5 text-xs text-[var(--text)] font-mono-data focus:border-[var(--accent)] focus:outline-none cursor-pointer"
              >
                {filteredQuestions.map((q) => (
                  <option key={q.question_id} value={q.question_id}>
                    [{q.question_id}] {q.product} ({q.gold_answer}) — {q.question.slice(0, 75)}...
                  </option>
                ))}
              </select>
            </div>

            {/* Top-K Selector */}
            <div className="md:col-span-2">
              <label className="block text-[10px] uppercase font-mono-data tracking-wider text-[var(--text-dim)] mb-1">
                Evidence Depth (Top-K)
              </label>
              <select
                aria-label="Evidence Depth Top K"
                value={topK}
                onChange={(e) => setTopK(Number(e.target.value))}
                className="w-full rounded-md border border-[var(--border)] bg-[var(--surface-3)] px-3 py-1.5 text-xs text-[var(--text)] font-mono-data focus:border-[var(--accent)] focus:outline-none cursor-pointer"
              >
                <option value={3}>Top 3 Docs</option>
                <option value={5}>Top 5 Docs (Standard)</option>
                <option value={8}>Top 8 Docs</option>
                <option value={10}>Top 10 Docs</option>
              </select>
            </div>
          </div>

          {/* Active Question Box & Enter Trigger */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-[11px] font-mono-data text-[var(--text-secondary)]">
              <div className="flex items-center gap-2">
                <span className="font-bold text-[var(--accent)]">
                  {selectedQuestionMeta ? selectedQuestionMeta.question_id : "CUSTOM"}
                </span>
                <span>·</span>
                <span>Target Product: <b className="text-[var(--text)]">{selectedQuestionMeta?.product || "Generic"}</b></span>
                <span>·</span>
                <span>Gold CVE: <b className="text-emerald-400 font-bold">{selectedQuestionMeta?.gold_answer || "N/A"}</b></span>
                <span>·</span>
                <span>CWE Class: <span className="text-[var(--text-dim)]">{selectedQuestionMeta?.target_cwe_class || "N/A"}</span></span>
              </div>
              <span className="text-[10px] text-[var(--text-dim)]">Press Enter in text box to execute</span>
            </div>

            <div className="flex gap-2">
              <input
                type="text"
                value={activeQuestionText}
                onChange={(e) => setActiveQuestionText(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && !runningBenchmark) {
                    void runSingleComparison();
                  }
                }}
                placeholder="Question text to query knowledge base..."
                className="flex-1 rounded-md border border-[var(--border)] bg-[var(--surface)] px-3.5 py-2 text-xs text-[var(--text)] focus:border-[var(--accent)] focus:outline-none"
              />
              <Button
                onClick={runSingleComparison}
                disabled={runningBenchmark || !activeQuestionText.trim()}
                variant="primary"
                size="md"
                icon={Play}
                className="px-5 font-semibold shrink-0"
              >
                {runningBenchmark ? "Evaluating 3 Arms..." : "Run 3-Way Comparison (Enter)"}
              </Button>
            </div>

            {selectedQuestionMeta?.summary && (
              <div className="text-[11px] font-mono-data text-[var(--text-muted)] bg-[var(--surface-3)]/40 rounded px-2.5 py-1 border border-[var(--border)]/60">
                <b className="text-[var(--text-dim)]">Ground Truth Mechanism:</b> {selectedQuestionMeta.summary}
              </div>
            )}
          </div>
        </div>

        {benchmarkError && (
          <div className="rounded-md border border-rose-500/40 bg-rose-500/10 p-3 text-xs font-mono-data text-rose-300 flex items-center gap-2">
            <AlertTriangle size={15} className="shrink-0 text-rose-400" />
            <span>{benchmarkError}</span>
          </div>
        )}

        {/* ------------------------------------------------------------- */}
        {/* 3-Column Comparative Output                                  */}
        {/* ------------------------------------------------------------- */}
        {activeComparison && (
          <div className="space-y-4 pt-2">
            <div className="flex items-center justify-between border-t border-[var(--border)] pt-4">
              <div className="text-xs font-mono-data text-[var(--text-dim)]">
                Empirical Results for: <span className="font-bold text-[var(--text)]">"{activeComparison.question}"</span>
                {activeComparison.gold_cve && (
                  <span> · Target Gold CVE: <span className="text-emerald-400 font-bold">{activeComparison.gold_cve}</span></span>
                )}
              </div>
              <span className="text-[11px] font-mono-data text-[var(--text-dim)]">{activeComparison.timestamp}</span>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              {activeComparison.arms.map((arm, armIdx) => {
                const isArm2 = arm.id === "hybrid_reranker";
                const isArm3 = arm.id === "hybrid_jev_reranker";

                const badgeColor = isArm3
                  ? "bg-emerald-500/15 border-emerald-500/40 text-emerald-400"
                  : isArm2
                  ? "bg-sky-500/15 border-sky-500/40 text-sky-400"
                  : "bg-indigo-500/15 border-indigo-500/40 text-indigo-400";

                return (
                  <div
                    key={arm.id}
                    className={`rounded-xl border flex flex-col justify-between p-4 transition-all ${
                      isArm3
                        ? "border-emerald-500/50 bg-[var(--surface-2)]/80 shadow-md shadow-emerald-950/20"
                        : "border-[var(--border)] bg-[var(--surface-2)]/40"
                    }`}
                  >
                    <div className="space-y-3">
                      {/* Arm Header */}
                      <div className="flex items-start justify-between gap-2 border-b border-[var(--border)] pb-2.5">
                        <div>
                          <div className="flex items-center gap-1.5">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-mono-data font-bold border ${badgeColor}`}>
                              Arm {armIdx + 1}
                            </span>
                            <h3 className="text-xs font-bold text-[var(--text)]">{arm.name}</h3>
                          </div>
                          <p className="text-[10px] text-[var(--text-dim)] mt-0.5 line-clamp-1">{arm.description}</p>
                        </div>

                        {/* Hit/Miss Badge */}
                        <div className="shrink-0">
                          {arm.hit ? (
                            <span className="inline-flex items-center gap-1 rounded bg-emerald-500/20 border border-emerald-500/40 px-2 py-0.5 text-[11px] font-mono-data font-bold text-emerald-400">
                              <CheckCircle2 size={13} /> Hit #{arm.rank}
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 rounded bg-rose-500/20 border border-rose-500/40 px-2 py-0.5 text-[11px] font-mono-data font-bold text-rose-400">
                              <XCircle size={13} /> Miss
                            </span>
                          )}
                        </div>
                      </div>

                      {/* Performance & Token Telemetry Card */}
                      <div className="grid grid-cols-2 gap-2 bg-[var(--surface-3)]/50 rounded-lg p-2.5 text-xs font-mono-data border border-[var(--border)]/70">
                        <div>
                          <span className="text-[9px] uppercase tracking-wider text-[var(--text-dim)] block">Total Latency</span>
                          <span className="font-bold text-[var(--text)] flex items-center gap-1">
                            <Clock size={11} className="text-[var(--text-dim)]" />
                            {arm.latency_ms} ms
                          </span>
                          <span className="text-[9px] text-[var(--text-dim)]">
                            Retr: {arm.retrieval_latency_ms}ms · Gen: {arm.generation_latency_ms}ms
                          </span>
                        </div>

                        <div>
                          <span className="text-[9px] uppercase tracking-wider text-[var(--text-dim)] block">Tokens (In / Out)</span>
                          <span className="font-bold text-[var(--text)] flex items-center gap-1">
                            <Layers size={11} className="text-[var(--text-dim)]" />
                            {arm.input_tokens} / {arm.output_tokens}
                          </span>
                          <span className="text-[9px] text-[var(--text-dim)]">
                            Total: {arm.total_tokens} tokens
                          </span>
                        </div>

                        <div className="col-span-2 pt-1.5 border-t border-[var(--border)]/50 flex items-center justify-between">
                          <span className="text-[10px] text-[var(--text-dim)] flex items-center gap-1">
                            <Coins size={11} className="text-amber-400" />
                            <span>Commercial 120B Rate:</span>
                          </span>
                          <div className="text-right">
                            <span className="font-bold text-emerald-400 text-xs">
                              ${arm.estimated_cost_usd.toFixed(6)}
                            </span>
                            <span className="text-[9px] text-[var(--text-dim)] block">
                              (Actual: $0.00 Free Tier)
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* Generated Answer */}
                      <div className="space-y-1">
                        <span className="text-[10px] uppercase font-mono-data tracking-wider text-[var(--text-dim)] block">
                          Generated Response (Grounded)
                        </span>
                        <div className="rounded-lg bg-[var(--surface)] border border-[var(--border)] p-3 text-xs text-[var(--text)] max-h-[160px] overflow-y-auto leading-relaxed whitespace-pre-wrap font-sans">
                          {arm.answer || "No response generated."}
                        </div>
                      </div>

                      {/* Retrieved Documents Accordion */}
                      <div className="space-y-1.5 pt-1">
                        <button
                          type="button"
                          onClick={() => toggleArmDocs(arm.id)}
                          className="flex items-center justify-between w-full text-[10px] uppercase font-mono-data tracking-wider text-[var(--text-dim)] hover:text-[var(--text)] transition-colors cursor-pointer py-0.5"
                        >
                          <span className="flex items-center gap-1">
                            {expandedDocsArm[arm.id] ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                            Retrieved Evidence Sources ({arm.retrieved_docs.length})
                          </span>
                          <span className="text-[9px] text-[var(--accent)] font-semibold">
                            {expandedDocsArm[arm.id] ? "Hide Sources" : "Show Sources"}
                          </span>
                        </button>

                        {expandedDocsArm[arm.id] && (
                          <div className="space-y-1.5 max-h-[220px] overflow-y-auto pr-0.5">
                            {arm.retrieved_docs.map((doc, docIdx) => {
                              const isTarget = activeComparison.gold_cve && doc.title.toUpperCase().includes(activeComparison.gold_cve.toUpperCase());
                              return (
                                <div
                                  key={`${doc.id}-${docIdx}`}
                                  className={`rounded-md border p-2 text-xs font-mono-data transition-all ${
                                    isTarget
                                      ? "border-emerald-500/60 bg-emerald-500/10"
                                      : "border-[var(--border)] bg-[var(--surface)]/70"
                                  }`}
                                >
                                  <div className="flex items-center justify-between gap-1.5 mb-1">
                                    <div className="flex items-center gap-1 truncate">
                                      <span className="text-[10px] text-[var(--text-dim)] font-bold">#{docIdx + 1}</span>
                                      <span className={`text-[11px] font-bold truncate ${isTarget ? "text-emerald-400" : "text-[var(--text)]"}`}>
                                        {doc.title}
                                      </span>
                                    </div>
                                    <div className="flex items-center gap-1 shrink-0">
                                      {isTarget && (
                                        <span className="rounded bg-emerald-500/20 px-1 py-0.2 text-[8px] font-bold text-emerald-400 border border-emerald-500/40">
                                          TARGET
                                        </span>
                                      )}
                                      <span className="rounded bg-[var(--surface-3)] px-1.5 py-0.5 text-[9px] text-[var(--text-dim)]">
                                        Score {doc.score}
                                      </span>
                                    </div>
                                  </div>
                                  <p className="text-[10px] text-[var(--text-muted)] line-clamp-2 leading-relaxed">
                                    {doc.snippet}
                                  </p>
                                </div>
                              );
                            })}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Session Benchmark Run History */}
        {sessionHistory.length > 0 && (
          <div className="border-t border-[var(--border)] pt-4 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase font-mono-data tracking-wider text-[var(--text-dim)]">
                Session Comparison History ({sessionHistory.length} Runs Logged)
              </span>
              <button
                type="button"
                onClick={exportSessionRuns}
                className="inline-flex items-center gap-1 text-[11px] font-mono-data text-[var(--accent)] hover:underline cursor-pointer"
              >
                <Download size={11} /> Export Session JSON
              </button>
            </div>

            <div className="overflow-x-auto rounded-lg border border-[var(--border)] bg-[var(--surface)]">
              <table className="w-full text-xs font-mono-data text-left">
                <thead className="bg-[var(--surface-2)] text-[10px] uppercase text-[var(--text-dim)] border-b border-[var(--border)]">
                  <tr>
                    <th className="py-2 px-3">Benchmark Question</th>
                    <th className="py-2 px-3">Target CVE</th>
                    <th className="py-2 px-3">Arm 1 (Hybrid)</th>
                    <th className="py-2 px-3">Arm 2 (+Re-ranker)</th>
                    <th className="py-2 px-3">Arm 3 (+JEV)</th>
                    <th className="py-2 px-3 text-right">Arm 3 Latency</th>
                    <th className="py-2 px-3 text-right">Tokens</th>
                    <th className="py-2 px-3 text-right">Est. Cost</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--border)]">
                  {sessionHistory.map((item, histIdx) => {
                    const arm1 = item.arms[0];
                    const arm2 = item.arms[1];
                    const arm3 = item.arms[2];
                    return (
                      <tr key={histIdx} className="hover:bg-[var(--surface-2)]/40 transition-colors">
                        <td className="py-2 px-3 text-[var(--text)] font-medium max-w-xs truncate">
                          {item.metadata?.question_id ? `[${item.metadata.question_id}] ` : ""}{item.question}
                        </td>
                        <td className="py-2 px-3 text-emerald-400 font-bold">{item.gold_cve || "—"}</td>
                        <td className="py-2 px-3">
                          {arm1?.hit ? (
                            <span className="text-emerald-400 font-semibold">Hit #{arm1.rank}</span>
                          ) : (
                            <span className="text-rose-400">Miss</span>
                          )}
                        </td>
                        <td className="py-2 px-3">
                          {arm2?.hit ? (
                            <span className="text-sky-400 font-semibold">Hit #{arm2.rank}</span>
                          ) : (
                            <span className="text-rose-400">Miss</span>
                          )}
                        </td>
                        <td className="py-2 px-3">
                          {arm3?.hit ? (
                            <span className="text-emerald-400 font-bold flex items-center gap-1">
                              <CheckCircle2 size={12} /> Hit #{arm3.rank}
                            </span>
                          ) : (
                            <span className="text-rose-400">Miss</span>
                          )}
                        </td>
                        <td className="py-2 px-3 text-right text-[var(--text-dim)]">{arm3?.latency_ms ?? 0} ms</td>
                        <td className="py-2 px-3 text-right text-[var(--text-dim)]">{arm3?.total_tokens ?? 0}</td>
                        <td className="py-2 px-3 text-right text-emerald-400 font-mono-data">
                          ${arm3?.estimated_cost_usd ? arm3.estimated_cost_usd.toFixed(6) : "0.000000"}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* ------------------------------------------------------------- */}
      {/* Existing Research Lab Sections (Backward Compatible)         */}
      {/* ------------------------------------------------------------- */}
      {/* Title & Run Action */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pt-4 border-t border-[var(--border)]">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--text)] flex items-center gap-2">
            <FlaskConical size={18} className="text-[var(--brand)]" />
            Empirical Research Lab &amp; Deduplication Benchmarks
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
          <div className="space-y-4">
            {featuredRun && featuredRetrieval && (
              <div className="space-y-3">
                <div className="text-[10px] uppercase tracking-wider text-[var(--text-dim)] font-mono-data">
                  Featured development run · {featuredRun.rows ?? "—"} cases
                </div>
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-2">
                  <MetricCard label="Recall@5" value={formatMetric(featuredRetrieval.recall_at_5)} />
                  <MetricCard label="MRR" value={formatMetric(featuredRetrieval.mrr)} />
                  <MetricCard label="nDCG@5" value={formatMetric(featuredRetrieval.ndcg_at_5)} />
                  <MetricCard label="Median latency" value={featuredLatency != null ? `${featuredLatency.toFixed(0)} ms` : "—"} />
                </div>
                <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-[var(--text-muted)] font-mono-data">
                  <span>{featuredRun.failures ?? 0} evaluation failures</span>
                  <span>{featuredRun.backend || "backend unavailable"} backend</span>
                  <span>index {featuredRun.index_state || "unknown"}</span>
                  <span>reranker fallbacks {featuredRun.reranker_fallback_count ?? 0}</span>
                </div>
              </div>
            )}
            <div className="space-y-1">
              <div className="text-[10px] uppercase tracking-wider text-[var(--text-dim)] font-mono-data">Run history</div>
              {ragRuns.map((run) => (
                <div key={run.run_id} className="border-b border-[var(--border)] py-2 text-xs font-mono-data">
                  <div className="flex items-center justify-between gap-3">
                    <span>{run.run_id}</span>
                    <span>{run.status} · {run.split || "unavailable"} · {run.rows ?? "?"} rows</span>
                  </div>
                  {run.metrics?.retrieval && (
                    <div className="mt-1 text-[var(--text-muted)]">
                      Recall@5 {formatMetric(run.metrics.retrieval.recall_at_5)} ·
                      MRR {formatMetric(run.metrics.retrieval.mrr)} ·
                      nDCG@5 {formatMetric(run.metrics.retrieval.ndcg_at_5)} ·
                      p50 {run.metrics.latency_ms?.p50 != null ? `${run.metrics.latency_ms.p50.toFixed(2)} ms` : "—"} ·
                      failures {run.failures ?? "—"} · {run.backend || "backend unavailable"}
                    </div>
                  )}
                </div>
              ))}
            </div>
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

function formatMetric(value?: number) {
  return value == null ? "—" : `${(value * 100).toFixed(2)}%`;
}

function MetricCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-[var(--border)] bg-[var(--surface-2)] px-3 py-2.5">
      <div className="text-[10px] uppercase tracking-wider text-[var(--text-dim)] font-mono-data">{label}</div>
      <div className="mt-1 text-lg font-bold text-[var(--brand)] font-mono-data">{value}</div>
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
