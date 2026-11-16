import React, { useState } from "react";
import { Check, Copy, ExternalLink } from "lucide-react";
import {
  parseMarkdownBlocks,
  parseInline,
} from "./markdown";

function InlineRenderer({ text }: { text: string }) {
  const tokens = parseInline(text);

  return (
    <>
      {tokens.map((token, index) => {
        switch (token.type) {
          case "text":
            return <React.Fragment key={index}>{token.text}</React.Fragment>;
          case "bold":
            return (
              <strong key={index} className="font-semibold text-[var(--text)]">
                {token.text}
              </strong>
            );
          case "italic":
            return (
              <em key={index} className="italic text-[var(--text)]">
                {token.text}
              </em>
            );
          case "code":
            return (
              <code
                key={index}
                className="font-mono-data bg-[var(--surface-3)] text-[var(--text)] border border-[var(--border)] px-1 py-0.5 rounded text-[11px] select-all"
              >
                {token.text}
              </code>
            );
          case "cve":
            return (
              <span
                key={index}
                className="font-mono-data font-medium text-[var(--accent)] bg-[var(--surface-2)] border border-[var(--border)] px-1.5 py-0.5 rounded text-[11px] inline-block tracking-tight"
              >
                {token.id}
              </span>
            );
          case "link":
            if (!token.isSafe) {
              return (
                <span key={index} className="text-[var(--text-secondary)] line-through" title="Unsafe link disarmed">
                  {token.text}
                </span>
              );
            }
            return (
              <a
                key={index}
                href={token.href}
                target="_blank"
                rel="noopener noreferrer"
                className="text-[var(--accent)] hover:text-[var(--accent-hover)] underline underline-offset-2 inline-flex items-center gap-0.5 font-normal"
              >
                <span>{token.text}</span>
                <ExternalLink size={10} className="inline opacity-70" />
              </a>
            );
        }
      })}
    </>
  );
}

function CodeBlockRenderer({ language, content }: { language: string; content: string }) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(content);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard write denied */
    }
  }

  return (
    <div className="my-2.5 rounded-[5px] border border-[var(--border)] bg-[var(--bg)] overflow-hidden">
      <div className="flex items-center justify-between px-3 py-1 bg-[var(--surface-2)] border-b border-[var(--border)] text-[10px] text-[var(--text-tertiary)] uppercase font-mono-data tracking-wider">
        <span>{language || "code"}</span>
        <button
          type="button"
          onClick={handleCopy}
          aria-label={copied ? "Copied code" : "Copy code"}
          className="flex items-center gap-1 text-[var(--text-secondary)] hover:text-[var(--text)] px-1.5 py-0.5 rounded hover:bg-[var(--surface-3)] transition-colors cursor-pointer"
        >
          {copied ? (
            <>
              <Check size={11} className="text-emerald-500" />
              <span className="text-emerald-500 normal-case">Copied</span>
            </>
          ) : (
            <>
              <Copy size={11} />
              <span className="normal-case">Copy</span>
            </>
          )}
        </button>
      </div>
      <pre className="p-3 text-[11.5px] leading-relaxed font-mono-data text-[var(--text)] overflow-x-auto whitespace-pre selection:bg-[var(--accent)] selection:text-[var(--accent-text)]">
        <code>{content}</code>
      </pre>
    </div>
  );
}

function TableRenderer({ headers, rows }: { headers: string[]; rows: string[][] }) {
  return (
    <div className="my-2.5 overflow-x-auto rounded-[5px] border border-[var(--border)]">
      <table className="min-w-full text-xs text-left divide-y divide-[var(--border)]">
        <thead className="bg-[var(--surface-2)] font-medium text-[var(--text)]">
          <tr>
            {headers.map((h, idx) => (
              <th key={idx} className="px-3 py-1.5 text-xs font-medium text-[var(--text-secondary)]">
                <InlineRenderer text={h} />
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-[var(--border)] bg-[var(--surface)]">
          {rows.map((row, rIdx) => (
            <tr key={rIdx} className="hover:bg-[var(--surface-2)]/50 transition-colors">
              {row.map((cell, cIdx) => (
                <td key={cIdx} className="px-3 py-1.5 text-xs text-[var(--text)] leading-relaxed">
                  <InlineRenderer text={cell} />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function MarkdownRenderer({
  content,
  className = "",
}: {
  content: string;
  className?: string;
}) {
  const blocks = parseMarkdownBlocks(content);

  if (blocks.length === 0) {
    return <span className="text-[var(--text-tertiary)] italic">No content</span>;
  }

  return (
    <div className={`space-y-2 text-xs leading-relaxed text-[var(--text)] break-words ${className}`}>
      {blocks.map((block, idx) => {
        switch (block.type) {
          case "code":
            return (
              <CodeBlockRenderer
                key={idx}
                language={block.language}
                content={block.content}
              />
            );
          case "heading": {
            if (block.level === 1) {
              return (
                <h1 key={idx} className="text-sm font-semibold text-[var(--text)] pt-2 pb-1 border-b border-[var(--border)]">
                  <InlineRenderer text={block.text} />
                </h1>
              );
            }
            if (block.level === 2) {
              return (
                <h2 key={idx} className="text-xs font-semibold text-[var(--text)] pt-1.5 pb-0.5">
                  <InlineRenderer text={block.text} />
                </h2>
              );
            }
            return (
              <h3 key={idx} className="text-xs font-medium text-[var(--text)] text-[var(--accent)] pt-1">
                <InlineRenderer text={block.text} />
              </h3>
            );
          }
          case "blockquote":
            return (
              <blockquote
                key={idx}
                className="border-l-2 border-[var(--accent)] pl-3 py-0.5 my-2 text-[var(--text-secondary)] italic bg-[var(--surface-2)]/30 rounded-r text-xs"
              >
                <InlineRenderer text={block.text} />
              </blockquote>
            );
          case "table":
            return <TableRenderer key={idx} headers={block.headers} rows={block.rows} />;
          case "list": {
            if (block.ordered) {
              return (
                <ol key={idx} className="list-decimal pl-5 space-y-1 my-1.5 text-xs text-[var(--text)]">
                  {block.items.map((item, itemIdx) => (
                    <li key={itemIdx}>
                      <InlineRenderer text={item} />
                    </li>
                  ))}
                </ol>
              );
            }
            return (
              <ul key={idx} className="list-disc pl-5 space-y-1 my-1.5 text-xs text-[var(--text)]">
                {block.items.map((item, itemIdx) => (
                  <li key={itemIdx}>
                    <InlineRenderer text={item} />
                  </li>
                ))}
              </ul>
            );
          }
          case "paragraph":
            return (
              <p key={idx} className="leading-relaxed">
                <InlineRenderer text={block.text} />
              </p>
            );
        }
      })}
    </div>
  );
}
