import React, { type ReactNode, useEffect } from "react";
import { type LucideIcon, Search, X, AlertCircle } from "lucide-react";

export function SeverityBadge({
  severity,
  className = "",
}: {
  severity: string;
  className?: string;
}) {
  const sev = severity?.toLowerCase() || "info";
  const label = severity ? severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase() : "Info";

  const dotClasses: Record<string, string> = {
    critical: "bg-[var(--critical)]",
    high: "bg-[var(--high)]",
    medium: "bg-[var(--medium)]",
    low: "bg-[var(--low)]",
    info: "bg-[var(--info)]",
  };

  const textClasses: Record<string, string> = {
    critical: "text-[var(--critical)]",
    high: "text-[var(--high)]",
    medium: "text-[var(--medium)]",
    low: "text-[var(--low)]",
    info: "text-[var(--info)]",
  };

  const activeDot = dotClasses[sev] || dotClasses.info;
  const activeText = textClasses[sev] || textClasses.info;

  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-medium ${activeText} ${className}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${activeDot} shrink-0`} />
      <span>{label}</span>
    </span>
  );
}

export function Tag({
  children,
  tone,
  className = "",
}: {
  children: ReactNode;
  tone?: "brand" | "critical" | "high" | "medium" | "low" | "muted";
  className?: string;
}) {
  const toneClasses: Record<string, string> = {
    brand: "text-[var(--text)] bg-[var(--surface-2)] border-[var(--border-strong)]",
    critical: "text-[var(--critical)] bg-[var(--critical-dim)] border-transparent",
    high: "text-[var(--high)] bg-[var(--high-dim)] border-transparent",
    medium: "text-[var(--medium)] bg-[var(--medium-dim)] border-transparent",
    low: "text-[var(--low)] bg-[var(--low-dim)] border-transparent",
    muted: "text-[var(--text-secondary)] bg-[var(--surface-2)] border-[var(--border)]",
  };
  const activeClass = toneClasses[tone || "muted"];

  return (
    <span
      className={`inline-flex items-center px-1.5 py-0.5 rounded-[4px] text-[11px] font-mono-data border mr-1.5 mb-1 ${activeClass} ${className}`}
    >
      {children}
    </span>
  );
}

export function Card({
  children,
  className = "",
  header,
  subtitle,
  action,
}: {
  children: ReactNode;
  className?: string;
  header?: ReactNode;
  subtitle?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div
      className={`bg-[var(--surface)] border border-[var(--border)] rounded-[5px] p-4 transition-colors ${className}`}
    >
      {(header || action) && (
        <div className="flex items-center justify-between gap-4 mb-3 pb-3 border-b border-[var(--border)]">
          <div>
            {typeof header === "string" ? (
              <h3 className="text-sm font-medium text-[var(--text)]">
                {header}
              </h3>
            ) : (
              header
            )}
            {subtitle && (
              <p className="text-xs text-[var(--text-secondary)] mt-0.5">{subtitle}</p>
            )}
          </div>
          {action && <div className="shrink-0">{action}</div>}
        </div>
      )}
      {children}
    </div>
  );
}

export function Button({
  children,
  onClick,
  variant = "primary",
  size = "md",
  disabled,
  type = "button",
  className = "",
  icon: Icon,
}: {
  children: ReactNode;
  onClick?: () => void;
  variant?: "primary" | "secondary" | "danger" | "ghost" | "outline";
  size?: "sm" | "md" | "lg";
  disabled?: boolean;
  type?: "button" | "submit";
  className?: string;
  icon?: LucideIcon;
}) {
  const sizeClasses = {
    sm: "px-2.5 py-1 text-xs gap-1.5 h-7",
    md: "px-3 py-1.5 text-xs gap-2 h-8",
    lg: "px-4 py-2 text-sm gap-2 h-9",
  };

  const variantClasses: Record<string, string> = {
    primary:
      "bg-[var(--accent)] text-[var(--accent-text)] hover:bg-[var(--accent-hover)] font-medium active:translate-y-px",
    secondary:
      "bg-[var(--surface-2)] text-[var(--text)] hover:bg-[var(--surface-3)] border border-[var(--border)] active:translate-y-px",
    outline:
      "bg-transparent text-[var(--text)] hover:bg-[var(--surface-2)] border border-[var(--border)] active:translate-y-px",
    danger:
      "bg-[var(--critical)] text-white hover:brightness-95 active:translate-y-px",
    ghost:
      "text-[var(--text-secondary)] hover:text-[var(--text)] hover:bg-[var(--surface-2)] active:translate-y-px",
  };

  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={`inline-flex items-center justify-center font-medium rounded-[5px] transition-colors cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed disabled:pointer-events-none select-none ${sizeClasses[size]} ${variantClasses[variant]} ${className}`}
    >
      {Icon && <Icon size={size === "sm" ? 13 : size === "lg" ? 16 : 14} className="shrink-0" />}
      {children}
    </button>
  );
}

export function Input({
  className = "",
  ...props
}: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className={`w-full bg-[var(--surface-2)] border border-[var(--border)] rounded-[5px] px-3 py-1.5 text-xs text-[var(--text)] placeholder:text-[var(--text-tertiary)] focus:border-[var(--accent)] focus:outline-none transition-colors ${className}`}
    />
  );
}

export function SearchInput({
  value,
  onChange,
  onClear,
  placeholder = "Search...",
  className = "",
  ...props
}: {
  value: string;
  onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  onClear?: () => void;
  placeholder?: string;
  className?: string;
} & Omit<React.InputHTMLAttributes<HTMLInputElement>, "onChange">) {
  return (
    <div className={`relative flex items-center ${className}`}>
      <Search size={14} className="absolute left-2.5 text-[var(--text-tertiary)] pointer-events-none" />
      <input
        type="text"
        aria-label={placeholder}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        {...props}
        className="w-full bg-[var(--surface-2)] border border-[var(--border)] rounded-[5px] pl-8 pr-7 py-1.5 text-xs text-[var(--text)] placeholder:text-[var(--text-tertiary)] focus:border-[var(--accent)] focus:outline-none transition-colors"
      />
      {value && (
        <button
          type="button"
          aria-label="Clear search input"
          onClick={onClear || (() => onChange({ target: { value: "" } } as any))}
          className="absolute right-2 text-[var(--text-tertiary)] hover:text-[var(--text)] p-0.5 rounded cursor-pointer"
        >
          <X size={12} />
        </button>
      )}
    </div>
  );
}

export function Select({
  children,
  className = "",
  ...props
}: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      {...props}
      className={`bg-[var(--surface-2)] border border-[var(--border)] rounded-[5px] px-3 py-1.5 text-xs text-[var(--text)] focus:border-[var(--accent)] focus:outline-none transition-colors cursor-pointer ${className}`}
    >
      {children}
    </select>
  );
}

export function KpiCard({
  label,
  value,
  accent,
  icon: Icon,
  badge,
  className = "",
}: {
  label: string;
  value: string | number;
  accent?: string;
  icon?: LucideIcon;
  badge?: string;
  className?: string;
}) {
  return (
    <div
      className={`flex-1 min-w-[140px] bg-[var(--surface)] border border-[var(--border)] rounded-[5px] p-3.5 flex flex-col justify-between ${className}`}
    >
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs text-[var(--text-secondary)] truncate">
          {label}
        </span>
        {Icon && <Icon size={14} className="text-[var(--text-tertiary)] shrink-0" />}
      </div>
      <div className="flex items-baseline justify-between gap-2">
        <div
          className="text-xl font-medium font-mono-data tracking-tight"
          style={{ color: accent || "var(--text)" }}
        >
          {value}
        </div>
        {badge && (
          <span className="text-[11px] font-mono-data text-[var(--text-tertiary)]">
            {badge}
          </span>
        )}
      </div>
    </div>
  );
}

export function EmptyState({
  title,
  hint,
  icon: Icon = AlertCircle,
  action,
}: {
  title: string;
  hint?: string;
  icon?: LucideIcon;
  action?: ReactNode;
}) {
  return (
    <div className="text-center py-12 px-4 flex flex-col items-center justify-center">
      <div className="w-9 h-9 rounded-[5px] bg-[var(--surface-2)] border border-[var(--border)] flex items-center justify-center mb-3 text-[var(--text-secondary)]">
        <Icon size={16} />
      </div>
      <div className="text-xs font-medium text-[var(--text)]">{title}</div>
      {hint && <div className="text-xs text-[var(--text-secondary)] mt-1 max-w-sm">{hint}</div>}
      {action && <div className="mt-3">{action}</div>}
    </div>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const norm = status?.toLowerCase() || "pending";
  const map: Record<string, { label: string; text: string; dot: string }> = {
    completed: { label: "Completed", text: "text-[var(--text)]", dot: "bg-emerald-500" },
    available: { label: "Available", text: "text-[var(--text)]", dot: "bg-emerald-500" },
    running: { label: "Running", text: "text-[var(--accent)]", dot: "bg-[var(--accent)]" },
    failed: { label: "Failed", text: "text-[var(--critical)]", dot: "bg-[var(--critical)]" },
    unconfigured: { label: "Not configured", text: "text-[var(--text-tertiary)]", dot: "bg-[var(--text-tertiary)]" },
    not_configured: { label: "Not configured", text: "text-[var(--text-tertiary)]", dot: "bg-[var(--text-tertiary)]" },
    pending: { label: "Pending", text: "text-[var(--text-secondary)]", dot: "bg-[var(--text-tertiary)]" },
    cancelled: { label: "Cancelled", text: "text-[var(--text-secondary)]", dot: "bg-[var(--text-tertiary)]" },
  };
  const config = map[norm] || { label: status, text: "text-[var(--text-secondary)]", dot: "bg-[var(--text-tertiary)]" };

  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-normal ${config.text}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${config.dot} shrink-0`} />
      <span>{config.label}</span>
    </span>
  );
}

export function Drawer({
  isOpen,
  onClose,
  title,
  subtitle,
  children,
  width = "540px",
}: {
  isOpen: boolean;
  onClose: () => void;
  title?: ReactNode;
  subtitle?: ReactNode;
  children: ReactNode;
  width?: string;
}) {
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape" && isOpen) onClose();
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 bg-[#000000]/50 flex items-center justify-end z-50"
      onClick={onClose}
    >
      <div
        className="bg-[var(--surface)] border-l border-[var(--border)] h-full overflow-y-auto flex flex-col shadow-xl"
        style={{ width, maxWidth: "100vw" }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="sticky top-0 z-10 bg-[var(--surface)] px-5 py-3.5 border-b border-[var(--border)] flex items-center justify-between">
          <div className="min-w-0 pr-4">
            {typeof title === "string" ? (
              <h2 className="text-sm font-medium text-[var(--text)] truncate">{title}</h2>
            ) : (
              title
            )}
            {subtitle && (
              <div className="text-xs text-[var(--text-secondary)] mt-0.5 truncate">{subtitle}</div>
            )}
          </div>
          <button
            onClick={onClose}
            aria-label="Close dialog"
            className="w-7 h-7 rounded-[4px] flex items-center justify-center text-[var(--text-secondary)] hover:text-[var(--text)] hover:bg-[var(--surface-2)] transition-colors cursor-pointer"
          >
            <X size={15} />
          </button>
        </div>
        <div className="p-5 flex-1">{children}</div>
      </div>
    </div>
  );
}
