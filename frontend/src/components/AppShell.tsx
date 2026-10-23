import { useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import {
  LayoutDashboard, Server, Radar, ShieldAlert, MessageSquareText,
  FileText, BookOpen, Users, CalendarClock, LogOut, KeyRound, Globe2,
  PanelLeftClose, PanelLeftOpen,
  FlaskConical,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { api } from "../api/client";

const NAV_ITEMS = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/assets", label: "Assets", icon: Server },
  { to: "/scans", label: "Scans", icon: Radar },
  { to: "/vulnerabilities", label: "Vulnerabilities", icon: ShieldAlert },
  { to: "/threat-intel", label: "Threat Intel", icon: Globe2 },
  { to: "/assistant", label: "AI Assistant", icon: MessageSquareText },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/knowledge", label: "Knowledge Base", icon: BookOpen },
  { to: "/research", label: "Research Lab", icon: FlaskConical },
  { to: "/schedules", label: "Schedules", icon: CalendarClock },
];

const SIDEBAR_STORAGE_KEY = "vuln_platform_sidebar_collapsed";

function navLinkClass(isActive: boolean, collapsed: boolean) {
  return `flex items-center gap-3 rounded-lg text-sm transition-colors ${collapsed ? "justify-center px-0 py-2.5" : "px-3 py-2"} ${
    isActive
      ? "bg-[var(--brand-dim)] text-[var(--brand)] font-semibold"
      : "text-[var(--text-muted)] hover:bg-[var(--surface-2)] hover:text-[var(--text)]"
  }`;
}

export default function AppShell() {
  const { user, logout, hasRole } = useAuth();
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem(SIDEBAR_STORAGE_KEY) === "true");

  function toggleCollapsed() {
    setCollapsed((prev) => {
      const next = !prev;
      try {
        localStorage.setItem(SIDEBAR_STORAGE_KEY, String(next));
      } catch {
        /* localStorage unavailable - collapse state just won't persist */
      }
      return next;
    });
  }

  async function changeOwnPassword() {
    const current = prompt("Enter your current password:");
    if (!current) return;
    const next = prompt("Enter your new password (min 8 characters):");
    if (!next) return;
    if (next.length < 8) {
      alert("New password must be at least 8 characters.");
      return;
    }
    try {
      await api.post("/auth/change-password", { current_password: current, new_password: next });
      alert("Password updated. Use it next time you log in.");
    } catch (err: any) {
      alert(err.message);
    }
  }

  return (
    <div className="flex h-screen bg-[var(--bg)]">
      <aside
        className={`border-r border-[var(--border)] bg-[var(--surface)] flex flex-col shrink-0 transition-[width] duration-200 ${
          collapsed ? "w-[68px]" : "w-60"
        }`}
      >
        <div className={`py-5 flex items-center border-b border-[var(--border)] ${collapsed ? "justify-center px-0" : "gap-2.5 px-5"}`}>
          <div className="w-8 h-8 rounded-lg bg-[var(--brand-dim)] flex items-center justify-center shrink-0">
            <ShieldAlert size={18} className="text-[var(--brand)]" />
          </div>
          {!collapsed && (
            <div className="min-w-0">
              <div className="font-bold text-sm leading-tight truncate">Watch Fortress</div>
              <div className="text-[10px] text-[var(--text-dim)] uppercase tracking-wider truncate">Vulnerability Assessment</div>
            </div>
          )}
        </div>

        <nav className={`flex-1 py-4 space-y-1 overflow-y-auto ${collapsed ? "px-2" : "px-3"}`}>
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              title={collapsed ? item.label : undefined}
              className={({ isActive }) => navLinkClass(isActive, collapsed)}
            >
              <item.icon size={16} className="shrink-0" />
              {!collapsed && item.label}
            </NavLink>
          ))}
          {hasRole("administrator", "auditor") && (
            <NavLink
              to="/admin"
              title={collapsed ? "Admin" : undefined}
              className={({ isActive }) => navLinkClass(isActive, collapsed)}
            >
              <Users size={16} className="shrink-0" />
              {!collapsed && "Admin"}
            </NavLink>
          )}
        </nav>

        <div className={`py-3 border-t border-[var(--border)] ${collapsed ? "px-2" : "px-4"}`}>
          {!collapsed && (
            <div className="flex items-center justify-between mb-2">
              <div className="min-w-0">
                <div className="text-sm font-medium truncate">{user?.username}</div>
                <div className="text-[10px] text-[var(--text-dim)] uppercase tracking-wide truncate">{user?.role.replace("_", " ")}</div>
              </div>
              <div className="flex items-center gap-1 shrink-0">
                <button onClick={changeOwnPassword} className="text-[var(--text-muted)] hover:text-[var(--brand)] p-1.5" title="Change password">
                  <KeyRound size={16} />
                </button>
                <button onClick={logout} className="text-[var(--text-muted)] hover:text-[var(--critical)] p-1.5" title="Log out">
                  <LogOut size={16} />
                </button>
              </div>
            </div>
          )}
          {collapsed && (
            <div className="flex flex-col items-center gap-1 mb-2">
              <button onClick={changeOwnPassword} className="text-[var(--text-muted)] hover:text-[var(--brand)] p-1.5" title="Change password">
                <KeyRound size={16} />
              </button>
              <button onClick={logout} className="text-[var(--text-muted)] hover:text-[var(--critical)] p-1.5" title="Log out">
                <LogOut size={16} />
              </button>
            </div>
          )}
          <button
            onClick={toggleCollapsed}
            className={`w-full flex items-center gap-2 text-xs text-[var(--text-dim)] hover:text-[var(--text)] hover:bg-[var(--surface-2)] rounded-lg py-1.5 transition-colors ${
              collapsed ? "justify-center" : "px-2 justify-start"
            }`}
            title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            {collapsed ? <PanelLeftOpen size={15} /> : <PanelLeftClose size={15} />}
            {!collapsed && "Collapse"}
          </button>
        </div>
      </aside>

      <main className="flex-1 overflow-y-auto">
        <div className="max-w-[1400px] mx-auto p-8">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
