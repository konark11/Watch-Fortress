import type { ReactNode } from "react";

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`sev-${severity} inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold uppercase tracking-wide`}>
      {severity}
    </span>
  );
}

export function Tag({ children, tone }: { children: ReactNode; tone?: "brand" | "critical" | "muted" }) {
  const toneClass =
    tone === "brand"
      ? "text-[var(--brand)] bg-[var(--brand-dim)]"
      : tone === "critical"
      ? "text-[var(--critical)] bg-[var(--critical-dim)]"
      : "text-[var(--text-muted)] bg-[var(--surface-2)]";
  return (
    <span className={`inline-block px-1.5 py-0.5 rounded text-[10.5px] font-mono-data mr-1 mb-1 ${toneClass}`}>
      {children}
    </span>
  );
}

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div
      className={`bg-[var(--surface)] border border-[var(--border)] rounded-xl p-5 shadow-[var(--shadow-sm)] transition-shadow hover:shadow-[var(--shadow-md)] ${className}`}
    >
      {children}
    </div>
  );
}

export function Button({
  children,
  onClick,
  variant = "primary",
  disabled,
  type = "button",
  className = "",
}: {
  children: ReactNode;
  onClick?: () => void;
  variant?: "primary" | "secondary" | "danger" | "ghost";
  disabled?: boolean;
  type?: "button" | "submit";
  className?: string;
}) {
  const base = "px-3.5 py-2 rounded-lg text-sm font-semibold transition-all disabled:opacity-50 disabled:cursor-not-allowed";
  const variants: Record<string, string> = {
    primary: "bg-[var(--brand)] text-[#0b0c0f] shadow-[var(--shadow-sm)] hover:brightness-110 hover:shadow-[var(--shadow-md)]",
    secondary: "bg-[var(--surface-3)] text-[var(--text)] hover:bg-[var(--surface-2)] border border-[var(--border)]",
    danger: "bg-[var(--critical)] text-white shadow-[var(--shadow-sm)] hover:brightness-110",
    ghost: "text-[var(--text-muted)] hover:text-[var(--text)] hover:bg-[var(--surface-2)]",
  };
  return (
    <button type={type} onClick={onClick} disabled={disabled} className={`${base} ${variants[variant]} ${className}`}>
      {children}
    </button>
  );
}

export function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className={`bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm text-[var(--text)] placeholder:text-[var(--text-dim)] focus:border-[var(--brand)] outline-none ${props.className || ""}`}
    />
  );
}

export function Select({ children, ...props }: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      {...props}
      className={`bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm text-[var(--text)] focus:border-[var(--brand)] outline-none ${props.className || ""}`}
    >
      {children}
    </select>
  );
}

export function KpiCard({ label, value, accent }: { label: string; value: string | number; accent?: string }) {
  return (
    <Card className="flex-1 min-w-[140px]">
      <div className="text-3xl font-bold font-mono-data" style={{ color: accent || "var(--text)" }}>
        {value}
      </div>
      <div className="text-xs text-[var(--text-muted)] uppercase tracking-wide mt-1">{label}</div>
    </Card>
  );
}

export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="text-center py-14 text-[var(--text-muted)]">
      <div className="text-sm font-medium text-[var(--text)]">{title}</div>
      {hint && <div className="text-xs mt-1">{hint}</div>}
    </div>
  );
}
