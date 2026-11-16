import { useEffect, useRef, useState, useCallback } from "react";
import {
  ArrowDown,
  Download,
  Edit3,
  PanelLeft,
  PanelLeftClose,
  Plus,
  RotateCw,
  Shield,
  WifiOff,
  BookOpen,
} from "lucide-react";
import { api } from "../api/client";
import type {
  Conversation,
  StoredMessage,
  Memory,
  RAGStatus,
  EvidenceSource,
} from "../components/assistant/types";
import { MessageBubble } from "../components/assistant/MessageBubble";
import { ChatComposer } from "../components/assistant/ChatComposer";
import { ConversationSidebar } from "../components/assistant/ConversationSidebar";
import { AssistantWelcome } from "../components/assistant/AssistantWelcome";
import { MemoriesDrawer } from "../components/assistant/MemoriesDrawer";
import {
  canSubmitMessage,
  sanitizeQuestionInput,
  formatAssistantError,
  isScrolledNearBottom,
  createLocalMessage,
} from "../components/assistant/assistant-logic";

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
  const [sidebarOpen, setSidebarOpen] = useState(() => {
    try {
      return localStorage.getItem("wf_assistant_sidebar_open") !== "false";
    } catch {
      return true;
    }
  });
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const [isMobile, setIsMobile] = useState(
    () => typeof window !== "undefined" && window.innerWidth < 768
  );
  const [memoriesOpen, setMemoriesOpen] = useState(false);
  const [showScrollBottom, setShowScrollBottom] = useState(false);

  const scrollRef = useRef<HTMLDivElement>(null);
  const abortControllerRef = useRef<AbortController | null>(null);
  const lastQuestionRef = useRef<string>("");

  useEffect(() => {
    function handleResize() {
      setIsMobile(window.innerWidth < 768);
    }
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, []);

  function handleToggleSidebar() {
    if (isMobile) {
      setMobileSidebarOpen((prev) => !prev);
    } else {
      setSidebarOpen((prev) => {
        const next = !prev;
        try {
          localStorage.setItem("wf_assistant_sidebar_open", String(next));
        } catch {
          /* ignore */
        }
        return next;
      });
    }
  }

  function handleCloseSidebar() {
    if (isMobile) {
      setMobileSidebarOpen(false);
    } else {
      setSidebarOpen(false);
      try {
        localStorage.setItem("wf_assistant_sidebar_open", "false");
      } catch {
        /* ignore */
      }
    }
  }

  // Load explicit memories
  const loadMemories = useCallback(async () => {
    try {
      const result = await api.get<{ memories: Memory[] }>("/assistant/memories");
      setMemories(Array.isArray(result?.memories) ? result.memories : []);
    } catch (err) {
      console.warn("Failed to load memories:", err);
    }
  }, []);

  // Select and load conversation
  const selectConversation = useCallback(async (id: string) => {
    setActiveId(id);
    setError(null);
    try {
      const result = await api.get<{ messages: StoredMessage[] }>(`/assistant/conversations/${id}`);
      setMessages(Array.isArray(result?.messages) ? result.messages : []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load conversation messages.");
      setMessages([]);
    }
  }, []);

  // Load all user conversations
  const loadConversations = useCallback(async () => {
    const result = await api.get<{ conversations: Conversation[] }>("/assistant/conversations");
    const nextConversations = Array.isArray(result?.conversations) ? result.conversations : [];
    setConversations(nextConversations);
    if (nextConversations[0]) {
      await selectConversation(nextConversations[0].id);
    }
  }, [selectConversation]);

  // Initial data loading
  useEffect(() => {
    Promise.allSettled([
      loadConversations().catch((err: Error) => {
        setError(err.message || "Assistant storage is unavailable.");
      }),
      loadMemories(),
      api.get<RAGStatus>("/assistant/status")
        .then((result) => setRagMode(result && typeof result === "object" ? result : null))
        .catch((err: Error) => console.warn("Failed to load assistant status:", err)),
    ]).finally(() => setLoading(false));
  }, [loadConversations, loadMemories]);

  // Auto-scroll logic: only scroll if user was already near bottom
  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    if (isScrolledNearBottom(el.scrollHeight, el.scrollTop, el.clientHeight, 120)) {
      el.scrollTo({ top: el.scrollHeight, behavior: "smooth" });
    }
  }, [messages, busy]);

  function handleScroll() {
    const el = scrollRef.current;
    if (!el) return;
    const nearBottom = isScrolledNearBottom(el.scrollHeight, el.scrollTop, el.clientHeight, 120);
    setShowScrollBottom(!nearBottom && el.scrollHeight > el.clientHeight);
  }

  function scrollToBottom() {
    const el = scrollRef.current;
    if (!el) return;
    el.scrollTo({ top: el.scrollHeight, behavior: "smooth" });
  }

  // Create new conversation
  async function handleNewConversation() {
    try {
      const created = await api.post<Conversation>("/assistant/conversations", {
        title: "New session",
      });
      setConversations((items) => [created, ...items]);
      setActiveId(created.id);
      setMessages([]);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Conversation could not be created.");
    }
  }

  // Remove conversation
  async function handleRemoveConversation(id: string) {
    try {
      await api.del(`/assistant/conversations/${id}`);
      const remaining = conversations.filter((c) => c.id !== id);
      setConversations(remaining);
      if (activeId === id) {
        if (remaining[0]) {
          await selectConversation(remaining[0].id);
        } else {
          setActiveId(null);
          setMessages([]);
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Conversation could not be deleted.");
    }
  }

  // Rename conversation
  async function handleRenameConversation(conversation: Conversation) {
    const title = window.prompt("Conversation title", conversation.title);
    if (!title || title.trim() === conversation.title) return;
    try {
      const updated = await api.patch<Conversation>(`/assistant/conversations/${conversation.id}`, {
        title: title.trim(),
      });
      setConversations((items) =>
        items.map((item) => (item.id === updated.id ? updated : item))
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Conversation could not be renamed.");
    }
  }

  // Cancel currently running request
  function handleCancelRequest() {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
  }

  // Send message
  async function handleSendMessage(customText?: string) {
    const rawQuestion = customText !== undefined ? customText : input;
    const question = sanitizeQuestionInput(rawQuestion);

    if (!canSubmitMessage(question, busy)) return;

    lastQuestionRef.current = question;
    let conversationId = activeId;
    const controller = new AbortController();
    abortControllerRef.current = controller;
    const timeout = window.setTimeout(() => controller.abort(), 90000);

    // Optimistically clear input and add user message
    if (customText === undefined) setInput("");
    setBusy(true);
    setError(null);

    const optimisticUserMsg = createLocalMessage("user", question);
    setMessages((prev) => [...prev, optimisticUserMsg]);

    try {
      if (!conversationId) {
        const created = await api.post<Conversation>("/assistant/conversations", {
          title: question.slice(0, 60),
        });
        conversationId = created.id;
        setActiveId(conversationId);
        setConversations((items) => [created, ...items]);
      }

      await api.post<{
        reply: string;
        sources?: EvidenceSource[];
        citations?: EvidenceSource[];
        message_id: string;
      }>("/assistant/ask", { question, conversation_id: conversationId }, controller.signal);

      // Fetch fresh server-persisted messages
      const refreshed = await api.get<{ messages: StoredMessage[] }>(
        `/assistant/conversations/${conversationId}`
      );
      setMessages(Array.isArray(refreshed?.messages) ? refreshed.messages : []);
    } catch (err) {
      const formatted = formatAssistantError(err, controller.signal.aborted);
      setError(formatted);
      const errorAssistantMsg = createLocalMessage("assistant", formatted, true);
      setMessages((prev) => [...prev, errorAssistantMsg]);
    } finally {
      window.clearTimeout(timeout);
      abortControllerRef.current = null;
      setBusy(false);
    }
  }

  // Retry last failed query
  function handleRetry() {
    if (lastQuestionRef.current) {
      handleSendMessage(lastQuestionRef.current);
    }
  }

  // Add explicit memory
  async function handleAddMemory(content: string) {
    await api.post("/assistant/memories", {
      memory_type: "preference",
      content,
      scope: "user",
    });
    await loadMemories();
  }

  // Remove memory
  async function handleRemoveMemory(id: string) {
    await api.del(`/assistant/memories/${id}`);
    await loadMemories();
  }

  // Export conversations and memories
  async function handleExport() {
    try {
      const data = await api.get<Record<string, unknown>>("/assistant/export");
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "watch-fortress-assistant-export.json";
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Export failed.");
    }
  }

  const activeConversation = conversations.find((c) => c.id === activeId);
  const isSidebarVisible = isMobile ? mobileSidebarOpen : sidebarOpen;

  return (
    <div className="flex h-full w-full bg-[var(--bg)] text-[var(--text)] overflow-hidden">
      {/* Persistent Conversation Sidebar with smooth width transition */}
      <ConversationSidebar
        conversations={conversations}
        activeId={activeId}
        onSelect={selectConversation}
        onNew={handleNewConversation}
        onDelete={handleRemoveConversation}
        onRename={handleRenameConversation}
        onOpenMemories={() => setMemoriesOpen(true)}
        onExport={handleExport}
        desktopOpen={sidebarOpen}
        mobileOpen={mobileSidebarOpen}
        onClose={handleCloseSidebar}
        memoryCount={memories.length}
      />

      {/* Main Chat Workspace */}
      <div className="flex-1 flex flex-col min-w-0 h-full relative overflow-hidden">
        {/* Workspace Top Bar */}
        <header className="h-11 border-b border-[var(--border)] bg-[var(--surface)] px-3 sm:px-4 flex items-center justify-between shrink-0 z-10">
          <div className="flex items-center gap-2 min-w-0">
            {/* Sidebar toggle button with collapse / expand state */}
            <button
              type="button"
              onClick={handleToggleSidebar}
              title={isSidebarVisible ? "Collapse chat history" : "Expand chat history"}
              aria-label={isSidebarVisible ? "Collapse chat history" : "Expand chat history"}
              className="p-1.5 text-[var(--text-secondary)] hover:text-[var(--text)] rounded-[4px] hover:bg-[var(--surface-2)] transition-colors cursor-pointer"
            >
              {isSidebarVisible ? <PanelLeftClose size={15} /> : <PanelLeft size={15} />}
            </button>

            {/* Active Conversation Title */}
            <div className="flex items-center gap-1.5 min-w-0">
              <span className="text-xs font-medium text-[var(--text)] truncate max-w-[180px] sm:max-w-xs">
                {activeConversation?.title || "New session"}
              </span>
              {activeConversation && (
                <button
                  type="button"
                  onClick={() => handleRenameConversation(activeConversation)}
                  title="Rename session"
                  aria-label="Rename session"
                  className="p-1 text-[var(--text-tertiary)] hover:text-[var(--text)] rounded cursor-pointer"
                >
                  <Edit3 size={11} />
                </button>
              )}
            </div>
          </div>

          {/* Right Action Controls */}
          <div className="flex items-center gap-2">
            {ragMode?.generation?.mode === "template" && (
              <span className="hidden sm:inline-flex items-center gap-1 text-[11px] font-mono-data text-[var(--text-secondary)] px-2 py-0.5 rounded bg-[var(--surface-2)] border border-[var(--border)]">
                <WifiOff size={11} />
                <span>Offline template</span>
              </span>
            )}

            <button
              type="button"
              onClick={() => setMemoriesOpen(true)}
              title="Explicit memories context"
              className="inline-flex items-center gap-1 text-xs text-[var(--text-secondary)] hover:text-[var(--text)] px-2 py-1 rounded hover:bg-[var(--surface-2)] transition-colors cursor-pointer"
            >
              <BookOpen size={12} className="text-[var(--accent)]" />
              <span className="hidden sm:inline">Memories</span>
              {memories.length > 0 && (
                <span className="font-mono-data text-[10px] bg-[var(--surface-3)] px-1 py-0.1 rounded text-[var(--text)]">
                  {memories.length}
                </span>
              )}
            </button>

            <button
              type="button"
              onClick={handleExport}
              title="Export conversations"
              aria-label="Export conversations"
              className="hidden sm:inline-flex items-center gap-1 text-xs text-[var(--text-secondary)] hover:text-[var(--text)] px-2 py-1 rounded hover:bg-[var(--surface-2)] transition-colors cursor-pointer"
            >
              <Download size={12} />
              <span>Export</span>
            </button>

            <button
              type="button"
              onClick={handleNewConversation}
              className="inline-flex items-center gap-1 text-xs font-medium bg-[var(--surface-2)] hover:bg-[var(--surface-3)] text-[var(--text)] border border-[var(--border)] px-2.5 py-1 rounded-[5px] transition-colors cursor-pointer"
            >
              <Plus size={12} className="text-[var(--accent)]" />
              <span className="hidden sm:inline">New chat</span>
            </button>
          </div>
        </header>

        {/* Global Alert Bar if initial load failed */}
        {error && messages.length === 0 && (
          <div role="alert" className="mx-4 mt-3 p-3 bg-[var(--critical-dim)] border border-[var(--critical)] rounded text-xs text-[var(--critical)] flex items-center justify-between gap-2">
            <span>{error}</span>
            <button
              type="button"
              onClick={() => loadConversations()}
              className="inline-flex items-center gap-1 underline text-xs font-medium cursor-pointer"
            >
              <RotateCw size={11} />
              <span>Retry connection</span>
            </button>
          </div>
        )}

        {/* Loading indicator during initial load */}
        {loading && (
          <div className="flex-1 flex items-center justify-center text-xs text-[var(--text-secondary)]">
            Loading assistant knowledge and sessions...
          </div>
        )}

        {/* Message Stream Scroll Area (Only this container scrolls) */}
        {!loading && (
          <div
            ref={scrollRef}
            onScroll={handleScroll}
            role="log"
            aria-live="polite"
            className="flex-1 overflow-y-auto px-2 sm:px-4 py-4 space-y-4"
          >
            {/* Empty State / Welcome Screen */}
            {messages.length === 0 ? (
              <AssistantWelcome onSelectPrompt={handleSendMessage} />
            ) : (
              messages.map((message, idx) => (
                <MessageBubble
                  key={message.id || `msg-${idx}`}
                  message={message}
                  onRetry={handleRetry}
                  isLatest={idx === messages.length - 1}
                />
              ))
            )}

            {/* In-conversation thinking / loading state */}
            {busy && (
              <div className="flex gap-3 max-w-4xl mx-auto px-2 sm:px-4 py-3 animate-pulse">
                <div className="w-7 h-7 rounded-full bg-[var(--accent-subtle)] text-[var(--accent)] border border-[var(--accent)]/30 flex items-center justify-center shrink-0">
                  <Shield size={14} />
                </div>
                <div className="space-y-1.5 flex-1 min-w-0">
                  <div className="text-[11px] font-medium text-[var(--text)]">Watch Fortress</div>
                  <div className="flex items-center gap-2 text-xs text-[var(--text-secondary)]">
                    <span className="w-2 h-2 rounded-full bg-[var(--accent)] animate-ping" />
                    <span>Retrieving evidence & synthesizing response...</span>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Floating "Jump to latest" pill */}
        {showScrollBottom && (
          <div className="absolute bottom-20 left-1/2 -translate-x-1/2 z-20">
            <button
              type="button"
              onClick={scrollToBottom}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-[var(--surface-2)] text-[var(--text)] border border-[var(--border-strong)] text-xs shadow-md hover:bg-[var(--surface-3)] transition-all cursor-pointer"
            >
              <ArrowDown size={12} className="text-[var(--accent)]" />
              <span>Jump to latest</span>
            </button>
          </div>
        )}

        {/* Sticky Chat Composer at Bottom */}
        <div className="shrink-0 bg-gradient-to-t from-[var(--bg)] via-[var(--bg)] to-transparent pt-2">
          <ChatComposer
            input={input}
            onChange={setInput}
            onSubmit={handleSendMessage}
            onCancel={handleCancelRequest}
            busy={busy}
            disabled={loading}
          />
        </div>
      </div>

      {/* Explicit Memories Drawer */}
      <MemoriesDrawer
        isOpen={memoriesOpen}
        onClose={() => setMemoriesOpen(false)}
        memories={memories}
        onAdd={handleAddMemory}
        onDelete={handleRemoveMemory}
      />
    </div>
  );
}
