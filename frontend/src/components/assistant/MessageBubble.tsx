import { useState } from "react";
import {
  BookOpen,
  Check,
  Copy,
  ExternalLink,
  RotateCw,
  Shield,
  User as UserIcon,
  AlertTriangle,
} from "lucide-react";
import { MarkdownRenderer } from "./MarkdownRenderer";
import { isSafeUrl } from "./markdown";
import type { StoredMessage, EvidenceSource } from "./types";

interface MessageBubbleProps {
  message: StoredMessage;
  onRetry?: () => void;
  isLatest?: boolean;
}

export function MessageBubble({ message, onRetry, isLatest }: MessageBubbleProps) {
  const [copied, setCopied] = useState(false);
  const isUser = message.role === "user";

  // Reconcile sources from either message.sources or message.citations (database format)
  const sources: EvidenceSource[] = Array.isArray(message.sources) && message.sources.length > 0
    ? message.sources
    : Array.isArray(message.citations)
    ? message.citations
    : [];

  const degradationReason = message.generation_metadata?.degradation?.reason;
  const latencyMs = message.generation_metadata?.latency_ms;
  const sourceMode = message.generation_metadata?.source_mode;
  const sourceModeLabel = sourceMode === "grounded"
    ? "Watch Fortress evidence"
    : sourceMode === "general"
    ? "General assistant knowledge"
    : sourceMode === "external"
    ? "External NVD source"
    : sourceMode === "insufficient_evidence"
    ? "Insufficient evidence"
    : null;

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(message.content);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard write denied */
    }
  }

  // Format timestamp if available
  const formattedTime = message.created_at
    ? new Date(message.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    : null;

  if (isUser) {
    return (
      <div className="flex justify-end gap-2.5 max-w-4xl mx-auto px-2 sm:px-4 py-2 group">
        <div className="flex flex-col items-end max-w-[85%] sm:max-w-[75%]">
          <div className="bg-[var(--surface-2)] border border-[var(--border-strong)] rounded-2xl rounded-tr-sm px-4 py-2.5 text-xs text-[var(--text)] leading-relaxed shadow-sm">
            <div className="whitespace-pre-wrap break-words">{message.content}</div>
          </div>
          <div className="flex items-center gap-2 mt-1 text-[10px] text-[var(--text-tertiary)] px-1">
            {formattedTime && <span>{formattedTime}</span>}
            <button
              type="button"
              onClick={handleCopy}
              title="Copy message"
              className="opacity-0 group-hover:opacity-100 hover:text-[var(--text)] transition-opacity cursor-pointer p-0.5"
            >
              {copied ? <Check size={11} className="text-emerald-500" /> : <Copy size={11} />}
            </button>
          </div>
        </div>
        <div className="w-7 h-7 rounded-full bg-[var(--surface-3)] border border-[var(--border)] flex items-center justify-center text-[var(--text-secondary)] shrink-0 mt-0.5" aria-hidden="true">
          <UserIcon size={14} />
        </div>
      </div>
    );
  }

  return (
    <div
      className={`flex gap-3 max-w-4xl mx-auto px-2 sm:px-4 py-3 group ${
        message.error ? "bg-[var(--critical-dim)]/20 border-l-2 border-[var(--critical)] rounded-r" : ""
      }`}
    >
      {/* Assistant Avatar */}
      <div
        className={`w-7 h-7 rounded-full flex items-center justify-center shrink-0 mt-0.5 ${
          message.error
            ? "bg-[var(--critical-dim)] text-[var(--critical)] border border-[var(--critical)]"
            : "bg-[var(--accent-subtle)] text-[var(--accent)] border border-[var(--accent)]/30"
        }`}
        aria-hidden="true"
      >
        <Shield size={14} />
      </div>

      {/* Main Message Content */}
      <div className="flex-1 min-w-0 space-y-2">
        {/* Header / Identity info */}
        <div className="flex items-center justify-between text-[11px] text-[var(--text-tertiary)]">
          <div className="flex items-center gap-2">
            <span className="font-medium text-[var(--text)] text-xs">Watch Fortress</span>
            {message.model && (
              <span className="font-mono-data text-[10px] px-1.5 py-0.2 rounded bg-[var(--surface-2)] border border-[var(--border)]">
                {message.model}
              </span>
            )}
            {latencyMs !== undefined && (
              <span className="font-mono-data text-[10px] text-[var(--text-tertiary)]">
                {latencyMs}ms
              </span>
            )}
            {sourceModeLabel && (
              <span className="font-mono-data text-[10px] px-1.5 py-0.2 rounded bg-[var(--surface-2)] border border-[var(--border)]">
                {sourceModeLabel}
              </span>
            )}
          </div>
          {formattedTime && <span className="font-mono-data text-[10px]">{formattedTime}</span>}
        </div>

        {/* Degradation notice if present */}
        {degradationReason && (
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[var(--surface-2)] border border-[var(--border)] text-[11px] text-[var(--text-secondary)]">
            <AlertTriangle size={12} className="text-amber-500 shrink-0" />
            <span>Response degraded: <strong className="font-mono-data">{degradationReason}</strong></span>
          </div>
        )}

        {/* Error notification banner if error */}
        {message.error ? (
          <div role="alert" className="p-3 rounded bg-[var(--surface)] border border-[var(--critical)] text-xs text-[var(--critical)] space-y-1.5">
            <div className="font-medium flex items-center gap-1.5">
              <AlertTriangle size={13} />
              <span>Request failed</span>
            </div>
            <p className="text-[var(--text)] leading-relaxed">{message.content}</p>
            {onRetry && isLatest && (
              <div className="pt-1">
                <button
                  type="button"
                  onClick={onRetry}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium bg-[var(--surface-2)] hover:bg-[var(--surface-3)] text-[var(--text)] border border-[var(--border)] transition-colors cursor-pointer"
                >
                  <RotateCw size={12} />
                  <span>Retry request</span>
                </button>
              </div>
            )}
          </div>
        ) : (
          /* Safe Markdown Body */
          <div className="text-xs leading-relaxed text-[var(--text)]">
            <MarkdownRenderer content={message.content} />
          </div>
        )}

        {/* Real Provenance / Citations */}
        {sources.length > 0 && !message.error && (
          <div className="mt-3 pt-2.5 border-t border-[var(--border)]">
            <div className="text-[11px] font-medium text-[var(--text-secondary)] mb-1.5 flex items-center gap-1.5">
              <BookOpen size={12} className="text-[var(--accent)]" />
              <span>Evidence sources ({sources.length})</span>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {sources.map((source, idx) => {
                const hasValidUrl = source.url && isSafeUrl(source.url);
                const relevancePct = source.relevance !== undefined ? Math.round(source.relevance * 100) : null;
                const sourceKey = source.id || `${source.source}-${source.title}-${idx}`;

                if (hasValidUrl && source.url) {
                  return (
                    <a
                      key={sourceKey}
                      href={source.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 bg-[var(--surface-2)] hover:bg-[var(--surface-3)] border border-[var(--border)] hover:border-[var(--accent)] rounded px-2 py-1 text-[11px] text-[var(--text)] transition-colors group/card"
                      title={source.title}
                    >
                      <span className="font-mono-data text-[10px] text-[var(--accent)] uppercase">{source.source}</span>
                      <span className="max-w-[200px] truncate">{source.title}</span>
                      {relevancePct !== null && (
                        <span className="font-mono-data text-[10px] text-[var(--text-tertiary)]">{relevancePct}%</span>
                      )}
                      <ExternalLink size={10} className="text-[var(--text-tertiary)] group-hover/card:text-[var(--accent)]" />
                    </a>
                  );
                }

                return (
                  <span
                    key={sourceKey}
                    className="inline-flex items-center gap-1.5 bg-[var(--surface-2)] border border-[var(--border)] rounded px-2 py-1 text-[11px] text-[var(--text)]"
                    title={source.title}
                  >
                    <span className="font-mono-data text-[10px] text-[var(--accent)] uppercase">{source.source}</span>
                    <span className="max-w-[240px] truncate">{source.title}</span>
                    {relevancePct !== null && (
                      <span className="font-mono-data text-[10px] text-[var(--text-tertiary)]">{relevancePct}%</span>
                    )}
                  </span>
                );
              })}
            </div>
          </div>
        )}

        {/* Message Footer / Copy action */}
        {!message.error && (
          <div className="flex items-center gap-2 pt-1 opacity-0 group-hover:opacity-100 transition-opacity">
            <button
              type="button"
              onClick={handleCopy}
              className="inline-flex items-center gap-1 text-[11px] text-[var(--text-tertiary)] hover:text-[var(--text)] px-1.5 py-0.5 rounded hover:bg-[var(--surface-2)] transition-colors cursor-pointer"
              title="Copy answer"
              aria-label={copied ? "Copied answer" : "Copy answer"}
            >
              {copied ? (
                <>
                  <Check size={11} className="text-emerald-500" />
                  <span className="text-emerald-500">Copied</span>
                </>
              ) : (
                <>
                  <Copy size={11} />
                  <span>Copy</span>
                </>
              )}
            </button>
            {onRetry && isLatest && (
              <button
                type="button"
                onClick={onRetry}
                className="inline-flex items-center gap-1 text-[11px] text-[var(--text-tertiary)] hover:text-[var(--text)] px-1.5 py-0.5 rounded hover:bg-[var(--surface-2)] transition-colors cursor-pointer"
                title="Regenerate response"
              >
                <RotateCw size={11} />
                <span>Retry</span>
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
