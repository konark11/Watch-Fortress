import { useEffect, useRef, useState } from "react";
import { Send, Sparkles, Wifi, WifiOff } from "lucide-react";
import { api } from "../api/client";
import type { AssistantResponse } from "../types";
import { Card, Button } from "../components/ui";

interface Message {
  role: "user" | "assistant";
  content: string;
  sources?: { source: string; title: string; relevance: number }[];
}

const EXAMPLE_QUESTIONS = [
  "Why is CVE-2024-3400 dangerous?",
  "How do I fix CVE-2017-5638?",
  "Show all critical findings",
  "Which hosts have privilege escalation risks?",
  "What is SQL injection?",
];

export default function AssistantPage() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [ragMode, setRagMode] = useState<{ mode: string; provider: string } | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    api.get<{ mode: string; provider: string }>("/assistant/status").then(setRagMode);
  }, []);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages]);

  async function send(question?: string) {
    const q = question ?? input;
    if (!q.trim()) return;
    setMessages((m) => [...m, { role: "user", content: q }]);
    setInput("");
    setBusy(true);
    try {
      const resp = await api.post<AssistantResponse>("/assistant/ask", { question: q });
      setMessages((m) => [...m, { role: "assistant", content: resp.answer, sources: resp.sources }]);
    } catch (err: any) {
      setMessages((m) => [...m, { role: "assistant", content: `Error: ${err.message || "something went wrong"}` }]);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col h-[calc(100vh-4rem)]">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-xl font-bold flex items-center gap-2">
            <Sparkles size={18} className="text-[var(--brand)]" /> AI Security Assistant
          </h1>
          <p className="text-sm text-[var(--text-muted)] mt-1">RAG-powered — retrieves from CVE/CWE/CAPEC/ATT&CK/OWASP and your live findings</p>
        </div>
        {ragMode && (
          <div className="flex items-center gap-1.5 text-xs text-[var(--text-muted)] bg-[var(--surface)] border border-[var(--border)] rounded-lg px-3 py-1.5">
            {ragMode.mode === "template" ? <WifiOff size={12} /> : <Wifi size={12} className="text-[var(--brand)]" />}
            {ragMode.provider}
          </div>
        )}
      </div>

      <Card className="flex-1 flex flex-col overflow-hidden p-0">
        <div ref={scrollRef} className="flex-1 overflow-y-auto p-5 space-y-4">
          {messages.length === 0 && (
            <div className="text-center py-10">
              <div className="text-sm text-[var(--text-muted)] mb-4">Try asking:</div>
              <div className="flex flex-wrap gap-2 justify-center max-w-lg mx-auto">
                {EXAMPLE_QUESTIONS.map((q) => (
                  <button
                    key={q}
                    onClick={() => send(q)}
                    className="text-xs bg-[var(--surface-2)] border border-[var(--border)] rounded-full px-3 py-1.5 text-[var(--text-muted)] hover:border-[var(--brand)] hover:text-[var(--text)] transition-colors"
                  >
                    {q}
                  </button>
                ))}
              </div>
            </div>
          )}
          {messages.map((m, i) => (
            <div key={i} className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}>
              <div
                className={`max-w-[75%] rounded-xl px-4 py-3 text-sm whitespace-pre-wrap ${
                  m.role === "user" ? "bg-[var(--brand-dim)] text-[var(--text)]" : "bg-[var(--surface-2)] text-[var(--text)]"
                }`}
              >
                {m.content}
                {m.sources && m.sources.length > 0 && (
                  <div className="mt-3 pt-3 border-t border-[var(--border-soft)] flex flex-wrap gap-1.5">
                    {m.sources.map((s, j) => (
                      <span key={j} className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--surface-3)] text-[var(--text-dim)]">
                        {s.source}: {s.title}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ))}
          {busy && <div className="text-xs text-[var(--text-dim)]">Thinking...</div>}
        </div>

        <div className="border-t border-[var(--border)] p-4 flex gap-2">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && send()}
            placeholder="Ask about a CVE, vulnerability type, or your scan results..."
            className="flex-1 bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 py-2.5 text-sm outline-none focus:border-[var(--brand)]"
          />
          <Button onClick={() => send()} disabled={busy}>
            <Send size={16} />
          </Button>
        </div>
      </Card>
    </div>
  );
}
