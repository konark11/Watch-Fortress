import { useState } from "react";
import { Trash2, Plus, BrainCircuit } from "lucide-react";
import { Drawer, Button, Input } from "../ui";
import type { Memory } from "./types";

interface MemoriesDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  memories: Memory[];
  onAdd: (content: string) => Promise<void>;
  onDelete: (id: string) => Promise<void>;
}

export function MemoriesDrawer({
  isOpen,
  onClose,
  memories,
  onAdd,
  onDelete,
}: MemoriesDrawerProps) {
  const [newContent, setNewContent] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleAdd(e: React.FormEvent) {
    e.preventDefault();
    if (!newContent.trim() || submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      await onAdd(newContent.trim());
      setNewContent("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add memory");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Drawer
      isOpen={isOpen}
      onClose={onClose}
      title="Explicit Memory"
      subtitle="Context directives included in future assistant queries"
      width="460px"
    >
      <div className="space-y-4">
        {/* Memory creation form */}
        <form onSubmit={handleAdd} className="space-y-2 p-3 bg-[var(--surface-2)] rounded-[5px] border border-[var(--border)]">
          <label htmlFor="memory-input" className="block text-xs font-medium text-[var(--text)]">
            Add context instruction or preference
          </label>
          <div className="flex gap-2">
            <Input
              id="memory-input"
              value={newContent}
              onChange={(e) => setNewContent(e.target.value)}
              placeholder="e.g. Always provide Ansible remediation tasks"
              disabled={submitting}
              className="flex-1"
            />
            <Button
              type="submit"
              variant="primary"
              size="sm"
              disabled={submitting || !newContent.trim()}
              icon={Plus}
            >
              Save
            </Button>
          </div>
          {error && <div className="text-[11px] text-[var(--critical)]">{error}</div>}
        </form>

        {/* Existing memories list */}
        <div className="space-y-2">
          <div className="text-[11px] font-mono-data uppercase text-[var(--text-tertiary)] tracking-wider">
            Active memories ({memories.length})
          </div>

          {memories.length === 0 ? (
            <div className="py-8 text-center text-xs text-[var(--text-secondary)] border border-dashed border-[var(--border)] rounded-[5px]">
              <BrainCircuit size={20} className="mx-auto mb-2 text-[var(--text-tertiary)]" />
              <span>No stored memories. Directives added here will persist across chats.</span>
            </div>
          ) : (
            <div className="space-y-2 max-h-[60vh] overflow-y-auto">
              {memories.map((item) => (
                <div
                  key={item.id}
                  className="flex items-start justify-between gap-3 p-3 bg-[var(--surface-2)] border border-[var(--border)] rounded-[5px] text-xs text-[var(--text)]"
                >
                  <div className="space-y-1 min-w-0">
                    <p className="font-medium text-xs break-words leading-relaxed">{item.content}</p>
                    <div className="flex items-center gap-2 text-[10px] font-mono-data text-[var(--text-tertiary)]">
                      <span className="capitalize">{item.scope} scope</span>
                      <span>·</span>
                      <span>Expires {new Date(item.expires_at).toLocaleDateString()}</span>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => onDelete(item.id)}
                    aria-label="Delete memory directive"
                    className="p-1 text-[var(--text-tertiary)] hover:text-[var(--critical)] transition-colors cursor-pointer shrink-0"
                  >
                    <Trash2 size={13} />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </Drawer>
  );
}
