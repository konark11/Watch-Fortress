import { useState } from "react";
import {
  MessageSquare,
  Plus,
  Trash2,
  Edit3,
  Download,
  BookOpen,
  PanelLeftClose,
  X,
} from "lucide-react";
import type { Conversation } from "./types";

interface ConversationSidebarProps {
  conversations: Conversation[];
  activeId: string | null;
  onSelect: (id: string) => void;
  onNew: () => void;
  onDelete: (id: string) => void;
  onRename: (conversation: Conversation) => void;
  onOpenMemories: () => void;
  onExport: () => void;
  desktopOpen: boolean;
  mobileOpen: boolean;
  onClose: () => void;
  memoryCount: number;
}

export function ConversationSidebar({
  conversations,
  activeId,
  onSelect,
  onNew,
  onDelete,
  onRename,
  onOpenMemories,
  onExport,
  desktopOpen,
  mobileOpen,
  onClose,
  memoryCount,
}: ConversationSidebarProps) {
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);

  function formatDate(iso?: string) {
    if (!iso) return "";
    try {
      const date = new Date(iso);
      const now = new Date();
      const diffMs = now.getTime() - date.getTime();
      const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

      if (diffDays === 0) return "Today";
      if (diffDays === 1) return "Yesterday";
      if (diffDays < 7) return `${diffDays}d ago`;
      return date.toLocaleDateString([], { month: "short", day: "numeric" });
    } catch {
      return "";
    }
  }

  return (
    <>
      {/* Mobile Backdrop */}
      {mobileOpen && (
        <div
          className="fixed inset-0 bg-[#000000]/60 z-30 md:hidden backdrop-blur-xs transition-opacity"
          onClick={onClose}
          aria-hidden="true"
        />
      )}

      {/* Sidebar Panel with smooth crunch animation on desktop and slide drawer on mobile */}
      <aside
        className={`fixed md:static inset-y-0 left-0 z-40 md:z-auto h-full bg-[var(--surface)] flex flex-col shrink-0 transition-all duration-200 ease-in-out overflow-hidden ${
          mobileOpen
            ? "translate-x-0 w-64 shadow-2xl border-r border-[var(--border)]"
            : "-translate-x-full md:translate-x-0"
        } ${
          desktopOpen
            ? "md:w-60 md:border-r md:border-[var(--border)] md:opacity-100"
            : "md:w-0 md:border-r-0 md:opacity-0 md:pointer-events-none"
        }`}
      >
        {/* Fixed-width inner container to prevent text wrapping or layout shifts during width transition */}
        <div className="w-64 md:w-60 h-full flex flex-col shrink-0">
          {/* Sidebar Header: "New Chat" & Close button */}
          <div className="p-3 border-b border-[var(--border)] flex items-center justify-between gap-2 shrink-0">
            <button
              type="button"
              onClick={() => {
                onNew();
                if (window.innerWidth < 768) onClose();
              }}
              className="flex-1 inline-flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-[5px] bg-[var(--surface-2)] hover:bg-[var(--surface-3)] text-xs font-medium text-[var(--text)] border border-[var(--border)] transition-colors cursor-pointer"
            >
              <Plus size={13} className="text-[var(--accent)]" />
              <span>New chat</span>
            </button>

            {/* Mobile close toggle */}
            <button
              type="button"
              onClick={onClose}
              aria-label="Close conversation history"
              className="md:hidden p-1.5 text-[var(--text-secondary)] hover:text-[var(--text)] rounded-[4px] hover:bg-[var(--surface-2)] transition-colors cursor-pointer"
            >
              <X size={15} />
            </button>
            {/* Desktop collapse icon */}
            <button
              type="button"
              onClick={onClose}
              aria-label="Collapse sidebar"
              title="Collapse sidebar"
              className="hidden md:flex p-1.5 text-[var(--text-tertiary)] hover:text-[var(--text)] rounded-[4px] hover:bg-[var(--surface-2)] transition-colors cursor-pointer"
            >
              <PanelLeftClose size={13} />
            </button>
          </div>

          {/* Conversation List */}
          <div className="flex-1 overflow-y-auto p-2 space-y-0.5">
            <div className="px-2 py-1 text-[10px] font-mono-data uppercase text-[var(--text-tertiary)] tracking-wider">
              History ({conversations.length})
            </div>

            {conversations.length === 0 ? (
              <div className="px-3 py-6 text-center text-xs text-[var(--text-tertiary)]">
                No previous conversations
              </div>
            ) : (
              conversations.map((item) => {
                const isActive = item.id === activeId;
                const isConfirmingDelete = deleteConfirmId === item.id;

                return (
                  <div
                    key={item.id}
                    className={`group relative flex items-center justify-between rounded-[5px] text-xs transition-colors ${
                      isActive
                        ? "bg-[var(--surface-2)] text-[var(--text)] font-medium"
                        : "text-[var(--text-secondary)] hover:bg-[var(--surface-hover)] hover:text-[var(--text)]"
                    }`}
                  >
                    {/* Left Active Indicator Bar */}
                    {isActive && (
                      <span className="absolute left-0 top-1.5 bottom-1.5 w-[2px] bg-[var(--accent)] rounded-r" />
                    )}

                    <button
                      type="button"
                      onClick={() => {
                        onSelect(item.id);
                        if (window.innerWidth < 768) onClose();
                      }}
                      className="flex-1 min-w-0 text-left px-2.5 py-1.5 flex items-center gap-2 cursor-pointer"
                      title={item.title}
                    >
                      <MessageSquare
                        size={13}
                        className={`shrink-0 ${
                          isActive ? "text-[var(--accent)]" : "text-[var(--text-tertiary)]"
                        }`}
                      />
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-xs">{item.title || "Untitled chat"}</div>
                        <div className="text-[10px] font-mono-data text-[var(--text-tertiary)] truncate">
                          {formatDate(item.updated_at || item.created_at)}
                        </div>
                      </div>
                    </button>

                    {/* Actions (Rename / Delete) */}
                    <div className="flex items-center gap-0.5 pr-1 shrink-0 opacity-0 group-hover:opacity-100 focus-within:opacity-100 transition-opacity">
                      {isConfirmingDelete ? (
                        <div className="flex items-center gap-1 bg-[var(--surface-3)] px-1 py-0.5 rounded">
                          <button
                            type="button"
                            onClick={() => {
                              onDelete(item.id);
                              setDeleteConfirmId(null);
                            }}
                            className="text-[10px] text-[var(--critical)] hover:underline font-medium px-1"
                          >
                            Confirm
                          </button>
                          <button
                            type="button"
                            onClick={() => setDeleteConfirmId(null)}
                            className="text-[10px] text-[var(--text-secondary)] hover:text-[var(--text)] px-1"
                          >
                            Cancel
                          </button>
                        </div>
                      ) : (
                        <>
                          <button
                            type="button"
                            onClick={() => onRename(item)}
                            title="Rename title"
                            aria-label={`Rename ${item.title}`}
                            className="p-1 text-[var(--text-tertiary)] hover:text-[var(--text)] hover:bg-[var(--surface-3)] rounded transition-colors cursor-pointer"
                          >
                            <Edit3 size={11} />
                          </button>
                          <button
                            type="button"
                            onClick={() => setDeleteConfirmId(item.id)}
                            title="Delete conversation"
                            aria-label={`Delete ${item.title}`}
                            className="p-1 text-[var(--text-tertiary)] hover:text-[var(--critical)] hover:bg-[var(--surface-3)] rounded transition-colors cursor-pointer"
                          >
                            <Trash2 size={11} />
                          </button>
                        </>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {/* Sidebar Footer: Memories & Export */}
          <div className="p-2 border-t border-[var(--border)] bg-[var(--surface)] space-y-1 shrink-0">
            <button
              type="button"
              onClick={onOpenMemories}
              className="w-full flex items-center justify-between px-2.5 py-1.5 rounded-[5px] text-xs text-[var(--text-secondary)] hover:text-[var(--text)] hover:bg-[var(--surface-2)] transition-colors cursor-pointer"
            >
              <span className="flex items-center gap-2">
                <BookOpen size={13} className="text-[var(--text-tertiary)]" />
                <span>Explicit memory</span>
              </span>
              {memoryCount > 0 && (
                <span className="font-mono-data text-[10px] bg-[var(--surface-3)] px-1.5 py-0.2 rounded text-[var(--text-secondary)]">
                  {memoryCount}
                </span>
              )}
            </button>

            <button
              type="button"
              onClick={onExport}
              className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded-[5px] text-xs text-[var(--text-secondary)] hover:text-[var(--text)] hover:bg-[var(--surface-2)] transition-colors cursor-pointer"
            >
              <Download size={13} className="text-[var(--text-tertiary)]" />
              <span>Export chats</span>
            </button>
          </div>
        </div>
      </aside>
    </>
  );
}
