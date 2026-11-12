import { useEffect, useState } from "react";
import { FlaskConical, Play } from "lucide-react";
import { api } from "../api/client";
import { Button, Card } from "../components/ui";

type Config = { id: string; label: string };
type Result = {
  configuration: string; question: string; provider?: string | null;
  answer?: string | null; latency_ms: number;
  retrieved: { id: string; source: string; title: string; score: number }[];
  errors: string[];
};

export default function ResearchPage() {
  const [configs, setConfigs] = useState<Config[]>([]);
  const [configuration, setConfiguration] = useState("vector_rag");
  const [question, setQuestion] = useState("What is SQL injection?");
  const [topK, setTopK] = useState(5);
  const [result, setResult] = useState<Result | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => { api.get<{ configurations: Config[] }>("/research/configurations").then((r) => setConfigs(r.configurations)); }, []);
  async function run() {
    setBusy(true);
    try { setResult(await api.post<Result>("/research/run", { question, configuration, top_k: topK })); }
    finally { setBusy(false); }
  }
  return <div className="space-y-5">
    <div><h1 className="text-xl font-bold flex items-center gap-2"><FlaskConical size={18} className="text-[var(--brand)]" /> Research Lab</h1><p className="text-sm text-[var(--text-muted)] mt-1">Run reproducible retrieval experiments without treating generated output as ground truth.</p></div>
    <Card className="space-y-4">
      <label className="block text-sm">Question<input value={question} onChange={(e) => setQuestion(e.target.value)} className="mt-1 w-full bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 py-2" /></label>
      <div className="flex flex-wrap gap-3 items-end">
        <label className="text-sm">Configuration<select value={configuration} onChange={(e) => setConfiguration(e.target.value)} className="block mt-1 bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 py-2">{configs.map((c) => <option key={c.id} value={c.id}>{c.label}</option>)}</select></label>
        <label className="text-sm">Top-k<input type="number" min={1} max={20} value={topK} onChange={(e) => setTopK(Number(e.target.value))} className="block mt-1 w-20 bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 py-2" /></label>
        <Button onClick={run} disabled={busy || !question.trim()}><Play size={14} /> {busy ? "Running..." : "Run experiment"}</Button>
      </div>
    </Card>
    {result && <Card><div className="flex justify-between text-xs text-[var(--text-muted)] mb-3"><span>{result.configuration}{result.provider ? ` · ${result.provider}` : ""}</span><span>{result.latency_ms} ms</span></div>{result.answer && <p className="text-sm whitespace-pre-wrap mb-4">{result.answer}</p>}<h2 className="font-semibold text-sm mb-2">Retrieved evidence</h2><div className="space-y-2">{result.retrieved.map((d) => <div key={d.id} className="text-xs border-b border-[var(--border-soft)] pb-2"><span className="text-[var(--brand)]">{d.score.toFixed(3)}</span> · {d.source} · {d.title}</div>)}</div></Card>}
  </div>;
}
