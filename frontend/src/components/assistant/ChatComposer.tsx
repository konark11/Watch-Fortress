import { useEffect, useRef, useLayoutEffect } from "react";
import { ArrowUp, Square } from "lucide-react";
import { evaluateComposerKeydown } from "./composer-behavior";

interface ChatComposerProps {
  input: string;
  onChange: (val: string) => void;
  onSubmit: (text?: string) => void;
  onCancel?: () => void;
  busy: boolean;
  placeholder?: string;
  disabled?: boolean;
}

export function ChatComposer({
  input,
  onChange,
  onSubmit,
  onCancel,
  busy,
  placeholder = "Ask about CVEs, recent scan findings, or remediation...",
  disabled = false,
}: ChatComposerProps) {
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Auto-resize textarea height to fit content
  useLayoutEffect(() => {
    const el = textareaRef.current;
    if (!el) return;
    el.style.height = "auto";
    const nextHeight = Math.min(el.scrollHeight, 200);
    el.style.height = `${Math.max(nextHeight, 42)}px`;
  }, [input]);

  // Maintain focus on the textarea when busy state turns off
  useEffect(() => {
    if (!busy && !disabled) {
      textareaRef.current?.focus();
    }
  }, [busy, disabled]);

  function handleKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    const decision = evaluateComposerKeydown(e.key, e.shiftKey, busy, input);
    if (decision.shouldPreventDefault) {
      e.preventDefault();
    }
    if (decision.shouldSubmit) {
      onSubmit();
    }
  }

  function handleFormSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (busy) {
      onCancel?.();
    } else if (input.trim() && !disabled) {
      onSubmit();
    }
  }

  const canSubmit = !busy && input.trim().length > 0 && !disabled;

  return (
    <div className="w-full max-w-4xl mx-auto px-3 sm:px-4 pb-3 pt-1">
      <form
        onSubmit={handleFormSubmit}
        className="relative bg-[var(--surface-2)] border border-[var(--border)] focus-within:border-[var(--accent)] rounded-2xl shadow-lg transition-colors p-2 sm:p-2.5 flex flex-col gap-1.5"
      >
        <textarea
          ref={textareaRef}
          value={input}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={disabled}
          rows={1}
          aria-label="Ask Watch Fortress Assistant"
          placeholder={placeholder}
          className="w-full bg-transparent border-0 resize-none px-2 py-1 text-xs text-[var(--text)] placeholder:text-[var(--text-tertiary)] focus:outline-none focus:ring-0 leading-relaxed max-h-[200px] overflow-y-auto"
        />

        <div className="flex items-center justify-between pt-1 px-1 text-[11px] text-[var(--text-tertiary)]">
          <div className="flex items-center gap-1.5 text-[10px]">
            <span className="hidden sm:inline">Enter to send · Shift+Enter for newline</span>
          </div>

          <div className="flex items-center gap-2">
            {busy ? (
              <button
                type="button"
                onClick={onCancel}
                aria-label="Stop generation"
                title="Stop generation"
                className="w-7 h-7 rounded-full bg-[var(--surface-3)] hover:bg-[var(--surface-active)] text-[var(--text)] border border-[var(--border-strong)] flex items-center justify-center transition-colors cursor-pointer"
              >
                <Square size={11} className="fill-current text-[var(--text)]" />
              </button>
            ) : (
              <button
                type="submit"
                disabled={!canSubmit}
                aria-label="Send message"
                title="Send message"
                className={`w-7 h-7 rounded-full flex items-center justify-center transition-all cursor-pointer ${
                  canSubmit
                    ? "bg-[var(--accent)] text-[var(--accent-text)] hover:bg-[var(--accent-hover)] shadow-sm"
                    : "bg-[var(--surface-3)] text-[var(--text-tertiary)] opacity-40 cursor-not-allowed"
                }`}
              >
                <ArrowUp size={14} className="stroke-[2.5]" />
              </button>
            )}
          </div>
        </div>
      </form>
    </div>
  );
}
