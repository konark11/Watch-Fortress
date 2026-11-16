import { ArrowRight, Shield, Terminal, ShieldAlert, FileSearch, Lock } from "lucide-react";
import type { StarterPrompt } from "./types";

const VERIFIED_STARTERS: StarterPrompt[] = [
  {
    id: "recent-scans",
    category: "Scans & Assets",
    title: "Recent scan findings",
    prompt: "What are the latest scan findings and remediation priorities?",
  },
  {
    id: "critical-findings",
    category: "Scans & Assets",
    title: "Critical findings summary",
    prompt: "Show all critical findings across assets.",
  },
  {
    id: "cve-terrapin",
    category: "CVE & Hardening",
    title: "CVE-2023-48795 (Terrapin)",
    prompt: "Explain CVE-2023-48795 (Terrapin) impact and provide verified remediation steps for SSH servers.",
  },
  {
    id: "openssh-harden",
    category: "CVE & Hardening",
    title: "OpenSSH hardening",
    prompt: "What are the recommended configuration directives to harden OpenSSH?",
  },
  {
    id: "audit-brute-force",
    category: "Audit & Intel",
    title: "Failed login analysis",
    prompt: "Review recent auth.login_failed audit logs for brute force signatures and IP correlation.",
  },
  {
    id: "cisa-kev",
    category: "Audit & Intel",
    title: "CISA KEV catalog check",
    prompt: "Which cataloged CISA KEV vulnerabilities are present in our environment?",
  },
];

const CATEGORY_ICONS = {
  "Scans & Assets": ShieldAlert,
  "CVE & Hardening": Lock,
  "Audit & Intel": FileSearch,
};

interface AssistantWelcomeProps {
  onSelectPrompt: (promptText: string) => void;
}

export function AssistantWelcome({ onSelectPrompt }: AssistantWelcomeProps) {
  return (
    <div className="max-w-3xl mx-auto px-4 py-8 sm:py-14 flex flex-col items-center text-center">
      {/* Brand & Emblem */}
      <div className="w-12 h-12 rounded-2xl bg-[var(--surface-2)] border border-[var(--border-strong)] flex items-center justify-center text-[var(--accent)] mb-4 shadow-sm">
        <Shield size={24} />
      </div>

      <h1 className="text-base sm:text-lg font-semibold text-[var(--text)] tracking-tight">
        Watch Fortress Assistant
      </h1>
      <p className="text-xs text-[var(--text-secondary)] mt-1.5 max-w-md leading-relaxed">
        Evidence-backed security intelligence, vulnerability triage, and verified operational remediation guidance.
      </p>

      {/* Starter Prompts Grid */}
      <div className="w-full mt-8 sm:mt-10">
        <div className="text-[11px] font-medium text-[var(--text-tertiary)] uppercase tracking-wider text-left mb-3 px-1 flex items-center gap-1.5">
          <Terminal size={12} />
          <span>Operational prompts</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-left">
          {VERIFIED_STARTERS.map((item) => {
            const Icon = CATEGORY_ICONS[item.category] || Shield;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => onSelectPrompt(item.prompt)}
                className="group relative flex flex-col justify-between p-3.5 rounded-[6px] bg-[var(--surface)] hover:bg-[var(--surface-2)] border border-[var(--border)] hover:border-[var(--accent)]/50 transition-all text-left cursor-pointer"
              >
                <div className="flex items-center justify-between gap-2 mb-1.5">
                  <span className="text-[10px] uppercase font-mono-data text-[var(--text-tertiary)] group-hover:text-[var(--accent)] transition-colors flex items-center gap-1">
                    <Icon size={11} />
                    <span>{item.category}</span>
                  </span>
                  <ArrowRight
                    size={12}
                    className="text-[var(--text-tertiary)] group-hover:text-[var(--text)] group-hover:translate-x-0.5 transition-all"
                  />
                </div>
                <div className="text-xs font-medium text-[var(--text)] mb-1">
                  {item.title}
                </div>
                <div className="text-[11px] text-[var(--text-secondary)] line-clamp-2 leading-relaxed">
                  {item.prompt}
                </div>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}
