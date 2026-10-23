import { useEffect, useRef, useState } from "react";
import { MessageSquare, Plus, Send, Sparkles, Trash2, Wifi, WifiOff } from "lucide-react";
import { api } from "../api/client";
import type { AssistantResponse } from "../types";
import { Card, Button } from "../components/ui";
import { useAuth } from "../context/AuthContext";

interface Message {
  role: "user" | "assistant";
  content: string;
  sources?: { source: string; title: string; relevance: number }[];
}

interface SavedChat {
  id: string;
  title: string;
  messages: Message[];
  updatedAt: number;
}

function renderMessage(content: string) {
  return content.split(/(\*\*[^*]+\*\*)/g).map((part, index) => {
    if (part.startsWith("**") && part.endsWith("**")) {
      return <strong key={index}>{part.slice(2, -2)}</strong>;
    }
    return <span key={index}>{part}</span>;
  });
}

const MAX_SAVED_CHATS = 5;
const CHAT_STORAGE_PREFIX = "watch-fortress-assistant-chats:";

const EXAMPLE_QUESTIONS = [
  "Why is CVE-2024-3400 dangerous?",
  "How do I fix CVE-2017-5638?",
  "Show all critical findings",
  "Which hosts have privilege escalation risks?",
  "What is SQL injection?",
];

export default function AssistantPage() {
  const { user } = useAuth();
  const [messages, setMessages] = useState<Message[]>([]);
  const [savedChats, setSavedChats] = useState<SavedChat[]>([]);
  const [activeChatId, setActiveChatId] = useState<string | null>(null);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [ragMode, setRagMode] = useState<{ mode: string; provider: string } | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const loadedChatsRef = useRef(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!user) return;
    const storageKey = `${CHAT_STORAGE_PREFIX}${user.id}`;
    try {
      const raw = localStorage.getItem(storageKey);
      const chats: SavedChat[] = raw ? JSON.parse(raw) : [];
      const validChats = Array.isArray(chats)
        ? chats.filter((chat) => chat && typeof chat.id === "string" && Array.isArray(chat.messages)).slice(0, MAX_SAVED_CHATS)
        : [];
      setSavedChats(validChats);
      if (validChats[0]) {
        setActiveChatId(validChats[0].id);
        setMessages(validChats[0].messages);
      }
    } catch {
      setSavedChats([]);
    } finally {
      loadedChatsRef.current = true;
    }
  }, [user]);

  useEffect(() => {
    api
      .get<{ mode: string; provider: string }>("/assistant/status")
      .then(setRagMode)
      .catch(() => setStatusError("Please try again later."));
  }, []);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages]);

  useEffect(() => {
    if (!user || !loadedChatsRef.current || !activeChatId || messages.length === 0) return;
    setSavedChats((current) => {
      const existing = current.find((chat) => chat.id === activeChatId);
      const firstQuestion = messages.find((message) => message.role === "user")?.content || "New conversation";
      const updated: SavedChat = {
        id: activeChatId,
        title: existing?.title || firstQuestion.slice(0, 60),
        messages,
        updatedAt: Date.now(),
      };
      const next = [updated, ...current.filter((chat) => chat.id !== activeChatId)].slice(0, MAX_SAVED_CHATS);
      try {
        localStorage.setItem(`${CHAT_STORAGE_PREFIX}${user.id}`, JSON.stringify(next));
      } catch {
        // Keep the active chat usable if browser storage is unavailable or full.
      }
      return next;
    });
  }, [messages, activeChatId, user]);

  function startNewChat() {
    setActiveChatId(null);
    setMessages([]);
    setInput("");
  }

  function openChat(chat: SavedChat) {
    setActiveChatId(chat.id);
    setMessages(chat.messages);
    setInput("");
  }

  function deleteChat(chatId: string) {
    setSavedChats((current) => {
      const next = current.filter((chat) => chat.id !== chatId);
      if (user) {
        try {
          localStorage.setItem(`${CHAT_STORAGE_PREFIX}${user.id}`, JSON.stringify(next));
        } catch {
          // The in-memory list still reflects the deletion for this session.
        }
      }
      return next;
    });
    if (activeChatId === chatId) {
      setActiveChatId(null);
      setMessages([]);
      setInput("");
    }
  }

  async function send(question?: string) {
    const q = question ?? input;
    if (!q.trim()) return;
    if (!activeChatId) setActiveChatId(`${Date.now()}-${Math.random().toString(36).slice(2)}`);
    setMessages((m) => [...m, { role: "user", content: q }]);
    setInput("");
    setBusy(true);
    try {
      const history = messages.slice(-8).map(({ role, content }) => ({ role, content }));
      const resp = await api.post<AssistantResponse>("/assistant/ask", { question: q, history });
      setMessages((m) => [...m, { role: "assistant", content: resp.answer, sources: resp.sources }]);
    } catch (err: any) {
      setMessages((m) => [...m, { role: "assistant", content: `I couldn't complete that. ${err.message || "Please try again."}` }]);
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
          <p className="text-sm text-[var(--text-muted)] mt-1">Ask about security issues, fixes, or your scan results.</p>
        </div>
        <div className="flex items-center gap-2">
          {ragMode && (
            <div className="flex items-center gap-1.5 text-xs text-[var(--text-muted)] bg-[var(--surface)] border border-[var(--border)] rounded-lg px-3 py-1.5">
              {ragMode.mode === "template" ? <WifiOff size={12} /> : <Wifi size={12} className="text-[var(--brand)]" />}
              Ready
            </div>
          )}
          <Button onClick={startNewChat} disabled={busy}>
            <Plus size={15} /> New chat
          </Button>
        </div>
        {statusError && <div className="text-xs text-red-400">The assistant status is unavailable: {statusError}</div>}
      </div>

      <Card className="flex-1 flex flex-col overflow-hidden p-0">
        {savedChats.length > 0 && (
          <div className="border-b border-[var(--border)] px-4 py-2 flex items-center gap-2 overflow-x-auto">
            <span className="text-[10px] uppercase tracking-wide text-[var(--text-dim)] shrink-0">Recent chats</span>
            {savedChats.map((chat) => (
              <div
                key={chat.id}
                className={`flex items-center gap-1 max-w-60 rounded-lg border transition-colors ${
                  chat.id === activeChatId
                    ? "border-[var(--brand)] bg-[var(--brand-dim)]"
                    : "border-[var(--border)]"
                }`}
              >
                <button
                  onClick={() => openChat(chat)}
                  title={chat.title}
                  className="flex items-center gap-1.5 min-w-0 text-xs rounded-l-lg px-2.5 py-1.5 text-[var(--text-muted)] hover:text-[var(--text)]"
                >
                  <MessageSquare size={12} className="shrink-0" />
                  <span className="truncate">{chat.title}</span>
                </button>
                <button
                  onClick={() => deleteChat(chat.id)}
                  title={`Delete chat: ${chat.title}`}
                  aria-label={`Delete chat: ${chat.title}`}
                  className="p-1.5 mr-0.5 rounded text-[var(--text-dim)] hover:text-[var(--critical)] hover:bg-[var(--surface-2)]"
                >
                  <Trash2 size={13} />
                </button>
              </div>
            ))}
          </div>
        )}
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
                {renderMessage(m.content)}
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
          {busy && <div className="text-xs text-[var(--text-dim)]">Looking into that...</div>}
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
