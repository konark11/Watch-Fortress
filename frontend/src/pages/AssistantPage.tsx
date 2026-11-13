import { useEffect, useRef, useState } from "react";
import { ArrowRight, BookOpen, Download, MessageSquare, Plus, Send, Trash2, WifiOff } from "lucide-react";
import { api } from "../api/client";
import type { AssistantStatus, ChatMessage, RAGStatus } from "../types";
import { Card, Button } from "../components/ui";

interface Conversation {
  id: string;
  title: string;
  status: "active" | "archived" | "deleted";
  expires_at: string;
}
interface StoredMessage extends ChatMessage {
  id: string;
  sequence: number;
  generation_metadata?: { degradation?: { reason?: string } | null };
}
interface Memory {
  id: string;
  memory_type: string;
  content: string;
  scope: "user" | "conversation";
  expires_at: string;
}

const SUGGESTIONS = [
  "Explain CVE-2023-48795 (Terrapin) impact and provide verified remediation steps for SSH servers.",
  "Review recent auth.login_failed audit logs for brute force signatures and IP correlation.",
  "Which cataloged CISA KEV vulnerabilities are present in our environment?",
  "What are the recommended configuration directives to harden OpenSSH?",
];

export default function AssistantPage() {
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [messages, setMessages] = useState<StoredMessage[]>([]);
  const [memories, setMemories] = useState<Memory[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [ragMode, setRagMode] = useState<RAGStatus | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  async function loadMemories() {
    const result = await api.get<{ memories: Memory[] }>("/assistant/memories");
    setMemories(Array.isArray(result?.memories) ? result.memories : []);
  }

  async function selectConversation(id: string) {
    setActiveId(id);
    const result = await api.get<{ messages: StoredMessage[] }>(`/assistant/conversations/${id}`);
    setMessages(Array.isArray(result?.messages) ? result.messages : []);
  }

  async function loadConversations() {
    const result = await api.get<{ conversations: Conversation[] }>("/assistant/conversations");
    const nextConversations = Array.isArray(result?.conversations) ? result.conversations : [];
    setConversations(nextConversations);
    if (nextConversations[0]) await selectConversation(nextConversations[0].id);
  }

  useEffect(() => {
    Promise.allSettled([
      loadConversations().catch((err: Error) => {
        setError(err.message || "Assistant storage is unavailable.");
      }),
      loadMemories().catch((err: Error) => {
        console.warn("Failed to load memories:", err);
        setError((current) => current || "Assistant memories are unavailable.");
      }),
      api.get<AssistantStatus>("/assistant/status")
        .then((result) => setRagMode(result && typeof result === "object" ? result : null))
        .catch((err: Error) => console.warn("Failed to load assistant status:", err)),
    ]).finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages, busy]);

  async function newConversation() {
    try {
      const created = await api.post<Conversation>("/assistant/conversations", { title: "New conversation" });
      setConversations((items) => [created, ...items]);
      await selectConversation(created.id);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Conversation could not be created.");
    }
  }

  async function removeConversation(id: string) {
    try {
      await api.del(`/assistant/conversations/${id}`);
      const remaining = conversations.filter((conversation) => conversation.id !== id);
      setConversations(remaining);
      if (activeId === id) {
        setActiveId(null);
        setMessages([]);
        if (remaining[0]) await selectConversation(remaining[0].id);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Conversation could not be deleted.");
    }
  }

  async function renameConversation(conversation: Conversation) {
    const title = window.prompt("Conversation title", conversation.title);
    if (!title || title === conversation.title) return;
    try {
      const updated = await api.patch<Conversation>(`/assistant/conversations/${conversation.id}`, { title });
      setConversations((items) => items.map((item) => item.id === updated.id ? updated : item));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Conversation could not be renamed.");
    }
  }

  async function send(text?: string) {
    const question = (text || input).trim();
    if (!question || busy) return;
    let conversationId = activeId;
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 90000);
    setBusy(true);
    setError(null);
    try {
      if (!conversationId) {
        const created = await api.post<Conversation>("/assistant/conversations", { title: question.slice(0, 60) });
        conversationId = created.id;
        setActiveId(conversationId);
        setConversations((items) => [created, ...items]);
      }
      const response = await api.post<{ reply: string; sources?: ChatMessage["sources"]; message_id: string }>(
        "/assistant/ask", { question, conversation_id: conversationId }, controller.signal,
      );
      const refreshed = await api.get<{ messages: StoredMessage[] }>(`/assistant/conversations/${conversationId}`);
      setMessages(refreshed.messages);
      setInput("");
      if (response.reply === undefined) setError("Assistant returned no persisted reply.");
    } catch (err) {
      setError(
        err instanceof DOMException && err.name === "AbortError"
          ? "Not persisted: assistant request timed out. Check the backend RAG status and try again."
          : err instanceof Error ? err.message : "Assistant request failed.",
      );
    } finally {
      window.clearTimeout(timeout);
      setBusy(false);
    }
  }

  async function addMemory() {
    const content = window.prompt("Save an explicit memory (it will be included in future assistant context).");
    if (!content?.trim()) return;
    try {
      await api.post("/assistant/memories", { memory_type: "preference", content: content.trim(), scope: "user" });
      await loadMemories();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Memory could not be saved.");
    }
  }

  async function exportData() {
    try {
      const data = await api.get<Record<string, unknown>>("/assistant/export");
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = "watch-fortress-assistant-export.json";
      link.click();
      URL.revokeObjectURL(link.href);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Export failed.");
    }
  }

  function renderMessage(message: StoredMessage) {
    const sources = Array.isArray(message.sources) ? message.sources : [];
    return (
      <div key={message.id} className={`flex gap-2.5 ${message.role === "user" ? "justify-end" : "justify-start"}`}>
        <div className={`max-w-[85%] rounded-[5px] p-3 text-xs leading-relaxed ${
          message.role === "user" ? "bg-[var(--surface-2)] border border-[var(--border-strong)]" : "border border-[var(--border)]"
        }`}>
          <div className="whitespace-pre-wrap">{message.content}</div>
          {sources.length > 0 && (
            <div className="mt-3 pt-2 border-t border-[var(--border)]">
              <div className="text-xs text-[var(--text-tertiary)] mb-1.5 flex items-center gap-1"><BookOpen size={11} /> Evidence sources</div>
              <div className="flex flex-wrap gap-1">{sources.map((source, idx) => (
                <span key={source.id || `${source.source}-${source.title}-${idx}`} className="bg-[var(--surface-2)] border border-[var(--border)] rounded px-1.5 py-0.5 text-xs">
                  {source.source}: {source.title}
                </span>
              ))}</div>
            </div>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-[calc(100vh-6rem)] space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div><h1 className="text-base font-semibold text-[var(--text)]">Remediation assistant</h1>
          <p className="text-xs text-[var(--text-secondary)]">Server-persisted conversations and explicit user memory.</p></div>
        <div className="flex items-center gap-2">
          {ragMode?.generation?.mode === "template" && <span className="text-xs text-[var(--text-secondary)] flex gap-1"><WifiOff size={12} /> Offline template</span>}
          <Button size="sm" variant="secondary" icon={Plus} onClick={newConversation}>New session</Button>
          <Button size="sm" variant="secondary" icon={Download} onClick={exportData}>Export</Button>
        </div>
      </div>
      {error && <div role="alert" className="text-xs text-[var(--critical)] border border-[var(--critical)] rounded p-2">{error}</div>}
      {loading && <div className="text-xs text-[var(--text-secondary)]">Loading assistant data...</div>}
      <Card className="flex-1 flex flex-col overflow-hidden p-0 border-[var(--border)]">
        <div className="bg-[var(--surface-2)] border-b border-[var(--border)] px-3 py-1.5 flex items-center gap-1.5 overflow-x-auto shrink-0">
          {conversations.map((conversation) => <div key={conversation.id} className="flex items-center border border-[var(--border)] rounded text-xs shrink-0">
            <button type="button" className="px-2 py-1 max-w-[160px] truncate" onClick={() => selectConversation(conversation.id)} onDoubleClick={() => renameConversation(conversation)}>
              <MessageSquare size={11} className="inline mr-1" />{conversation.title}
            </button>
            <button type="button" className="p-1 text-[var(--text-tertiary)] hover:text-[var(--critical)]" onClick={() => removeConversation(conversation.id)} title="Delete conversation"><Trash2 size={11} /></button>
          </div>)}
        </div>
        <div ref={scrollRef} className="flex-1 overflow-y-auto p-4 space-y-4">
          {messages.length === 0 && <div className="max-w-xl mx-auto py-10 text-center space-y-4">
            <h3 className="text-sm font-medium">Remediation Assistant</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-left">{SUGGESTIONS.map((suggestion) => <button key={suggestion} type="button" onClick={() => send(suggestion)} className="p-2.5 rounded border border-[var(--border)] text-xs text-left"><ArrowRight size={12} className="inline mr-1" />{suggestion}</button>)}</div>
          </div>}
          {messages.map(renderMessage)}
          {busy && <div className="text-xs text-[var(--text-secondary)]">Retrieving knowledge and persisting response...</div>}
        </div>
        <div className="p-3 bg-[var(--surface)] border-t border-[var(--border)]">
          <form onSubmit={(event) => { event.preventDefault(); send(); }} className="flex gap-2">
            <input aria-label="Ask security assistant" value={input} onChange={(event) => setInput(event.target.value)} disabled={busy} className="flex-1 bg-[var(--surface-2)] border border-[var(--border)] rounded px-3 py-1.5 text-xs" placeholder="Ask about CVEs or remediation..." />
            <Button type="submit" variant="primary" disabled={busy || !input.trim()} icon={Send}>Ask</Button>
          </form>
        </div>
      </Card>
      <Card className="shrink-0 p-3">
        <div className="flex items-center justify-between"><h2 className="text-xs font-semibold">Explicit memory</h2><Button size="sm" variant="secondary" onClick={addMemory}>Add</Button></div>
        {memories.length === 0 ? <p className="text-xs text-[var(--text-secondary)] mt-2">No stored memories.</p> : memories.map((memory) => <div key={memory.id} className="flex items-center justify-between gap-2 mt-2 text-xs"><span className="truncate">{memory.content} <span className="text-[var(--text-tertiary)]">expires {new Date(memory.expires_at).toLocaleDateString()}</span></span><button type="button" onClick={() => api.del(`/assistant/memories/${memory.id}`).then(loadMemories).catch((err: Error) => setError(err.message))} title="Delete memory"><Trash2 size={13} /></button></div>)}
      </Card>
    </div>
  );
}
