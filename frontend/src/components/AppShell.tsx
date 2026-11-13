import { useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import {
  LayoutDashboard, Server, Radar, ShieldAlert, MessageSquareText,
  FileText, BookOpen, CalendarClock, LogOut, KeyRound, Globe2,
  PanelLeftClose, PanelLeftOpen, FlaskConical, Users
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { api } from "../api/client";

interface NavItem {
  to: string;
  label: string;
  icon: any;
  end?: boolean;
}

interface NavSection {
  title: string;
  items: NavItem[];
}

const NAV_SECTIONS: NavSection[] = [
  {
    title: "Operations",
    items: [
      { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
      { to: "/scans", label: "Scans", icon: Radar },
      { to: "/vulnerabilities", label: "Vulnerabilities", icon: ShieldAlert },
      { to: "/assets", label: "Assets", icon: Server },
    ],
  },
  {
    title: "Intelligence",
    items: [
      { to: "/threat-intel", label: "Threat intelligence", icon: Globe2 },
      { to: "/assistant", label: "Remediation assistant", icon: MessageSquareText },
      { to: "/reports", label: "Reports", icon: FileText },
    ],
  },
  {
    title: "System",
    items: [
      { to: "/knowledge", label: "Knowledge base", icon: BookOpen },
      { to: "/research", label: "Research lab", icon: FlaskConical },
      { to: "/schedules", label: "Schedules", icon: CalendarClock },
    ],
  },
];

const SIDEBAR_STORAGE_KEY = "vuln_platform_sidebar_collapsed";

export default function AppShell() {
  const { user, logout, hasRole } = useAuth();
  const location = useLocation();
  const [collapsed, setCollapsed] = useState(
    () => localStorage.getItem(SIDEBAR_STORAGE_KEY) === "true"
  );

  function toggleCollapsed() {
    setCollapsed((prev) => {
      const next = !prev;
      try {
        localStorage.setItem(SIDEBAR_STORAGE_KEY, String(next));
      } catch {
        /* storage unavailable */
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
      alert("Password updated successfully.");
    } catch (err: any) {
      alert(err.message || "Failed to update password");
    }
  }

  const activeItem = [
    ...NAV_SECTIONS.flatMap((s) => s.items),
    { to: "/admin", label: "Administration", icon: Users },
  ].find((item) => (item.end ? location.pathname === item.to : location.pathname.startsWith(item.to)));

  const pageTitle = activeItem ? activeItem.label : "Console";

  return (
    <div className="flex h-screen bg-[var(--bg)] text-[var(--text)] overflow-hidden">
      {/* Left Navigation */}
      <aside
        className={`border-r border-[var(--border)] bg-[var(--surface)] flex flex-col shrink-0 transition-all duration-150 z-20 ${
          collapsed ? "w-14" : "w-56"
        }`}
      >
        {/* Plain wordmark header */}
        <div
          className={`h-12 flex items-center border-b border-[var(--border)] px-3.5 ${
            collapsed ? "justify-center" : "justify-between"
          }`}
        >
          {!collapsed ? (
            <div className="flex items-center gap-2">
              <span className="font-semibold text-xs tracking-tight text-[var(--text)]">
                Watch Fortress
              </span>
              <span className="text-[10px] text-[var(--text-tertiary)] font-mono-data">v1.2</span>
            </div>
          ) : (
            <span className="font-semibold text-xs text-[var(--text)]">WF</span>
          )}
          {!collapsed && (
            <button
              onClick={toggleCollapsed}
              className="text-[var(--text-tertiary)] hover:text-[var(--text)] p-1 rounded-[4px] hover:bg-[var(--surface-2)] transition-colors cursor-pointer"
              title="Collapse sidebar"
              aria-label="Collapse sidebar"
            >
              <PanelLeftClose size={14} />
            </button>
          )}
        </div>

        {/* Navigation list */}
        <nav className="flex-1 py-3 px-2 overflow-y-auto space-y-4">
          {NAV_SECTIONS.map((section) => (
            <div key={section.title} className="space-y-0.5">
              {!collapsed && (
                <div className="px-2 py-1 text-[11px] font-normal text-[var(--text-tertiary)]">
                  {section.title}
                </div>
              )}
              {section.items.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.end}
                  title={collapsed ? item.label : undefined}
                  className={({ isActive }) =>
                    `group relative flex items-center gap-2.5 rounded-[5px] text-xs font-normal transition-colors ${
                      collapsed ? "justify-center px-0 py-2" : "px-2.5 py-1.5"
                    } ${
                      isActive
                        ? "bg-[var(--surface-2)] text-[var(--text)] font-medium"
                        : "text-[var(--text-secondary)] hover:bg-[var(--surface-hover)] hover:text-[var(--text)]"
                    }`
                  }
                >
                  {({ isActive }) => (
                    <>
                      {isActive && (
                        <span className="absolute left-0 top-1.5 bottom-1.5 w-[2px] bg-[var(--accent)] rounded-r" />
                      )}
                      <item.icon
                        size={15}
                        className={`shrink-0 ${
                          isActive ? "text-[var(--accent)]" : "text-[var(--text-tertiary)] group-hover:text-[var(--text-secondary)]"
                        }`}
                      />
                      {!collapsed && <span className="truncate">{item.label}</span>}
                    </>
                  )}
                </NavLink>
              ))}
            </div>
          ))}

          {/* Administration section if authorized */}
          {hasRole("administrator", "auditor") && (
            <div className="space-y-0.5 pt-2 border-t border-[var(--border)]">
              {!collapsed && (
                <div className="px-2 py-1 text-[11px] font-normal text-[var(--text-tertiary)]">
                  Access
                </div>
              )}
              <NavLink
                to="/admin"
                title={collapsed ? "Administration" : undefined}
                className={({ isActive }) =>
                  `group relative flex items-center gap-2.5 rounded-[5px] text-xs font-normal transition-colors ${
                    collapsed ? "justify-center px-0 py-2" : "px-2.5 py-1.5"
                  } ${
                    isActive
                      ? "bg-[var(--surface-2)] text-[var(--text)] font-medium"
                      : "text-[var(--text-secondary)] hover:bg-[var(--surface-hover)] hover:text-[var(--text)]"
                  }`
                }
              >
                {({ isActive }) => (
                  <>
                    {isActive && (
                      <span className="absolute left-0 top-1.5 bottom-1.5 w-[2px] bg-[var(--accent)] rounded-r" />
                    )}
                    <Users
                      size={15}
                      className={`shrink-0 ${
                        isActive ? "text-[var(--accent)]" : "text-[var(--text-tertiary)] group-hover:text-[var(--text-secondary)]"
                      }`}
                    />
                    {!collapsed && <span className="truncate">Administration</span>}
                  </>
                )}
              </NavLink>
            </div>
          )}
        </nav>

        {/* Collapsed expand toggle */}
        {collapsed && (
          <div className="p-2 border-t border-[var(--border)] flex justify-center">
            <button
              onClick={toggleCollapsed}
              className="text-[var(--text-tertiary)] hover:text-[var(--text)] p-1.5 rounded-[4px] hover:bg-[var(--surface-2)] transition-colors cursor-pointer"
              title="Expand sidebar"
              aria-label="Expand sidebar"
            >
              <PanelLeftOpen size={14} />
            </button>
          </div>
        )}

        {/* User profile footer */}
        <div className="p-2 border-t border-[var(--border)] bg-[var(--surface)]">
          <div className={`flex items-center ${collapsed ? "justify-center" : "justify-between"} gap-2`}>
            <div className="flex items-center gap-2 min-w-0">
              <div className="w-6 h-6 rounded-[4px] bg-[var(--surface-2)] border border-[var(--border)] flex items-center justify-center font-mono-data text-[11px] text-[var(--text-secondary)] shrink-0">
                {user?.username?.slice(0, 2).toUpperCase() || "OP"}
              </div>
              {!collapsed && (
                <div className="min-w-0">
                  <div className="text-xs font-normal text-[var(--text)] truncate">
                    {user?.username}
                  </div>
                  <div className="text-[11px] text-[var(--text-tertiary)] capitalize truncate">
                    {user?.role?.replace("_", " ")}
                  </div>
                </div>
              )}
            </div>

            {!collapsed && (
              <div className="flex items-center gap-0.5 shrink-0">
                <button
                  onClick={changeOwnPassword}
                  className="p-1 rounded-[4px] text-[var(--text-tertiary)] hover:text-[var(--text)] hover:bg-[var(--surface-2)] transition-colors cursor-pointer"
                  title="Change Password"
                  aria-label="Change Password"
                >
                  <KeyRound size={13} />
                </button>
                <button
                  onClick={logout}
                  className="p-1 rounded-[4px] text-[var(--text-tertiary)] hover:text-[var(--critical)] hover:bg-[var(--surface-2)] transition-colors cursor-pointer"
                  title="Sign Out"
                  aria-label="Sign Out"
                >
                  <LogOut size={13} />
                </button>
              </div>
            )}
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 h-screen overflow-hidden">
        {/* Top Header Bar */}
        <header className="h-12 border-b border-[var(--border)] bg-[var(--surface)] px-5 flex items-center justify-between shrink-0 z-10">
          <div className="flex items-center gap-2 text-xs">
            <span className="text-[var(--text-tertiary)]">Watch Fortress</span>
            <span className="text-[var(--text-tertiary)]">/</span>
            <span className="font-medium text-[var(--text)]">{pageTitle}</span>
          </div>

          <div className="flex items-center gap-3">
            {/* Real status line: plain small dot + text */}
            <div className="flex items-center gap-1.5 text-xs text-[var(--text-secondary)]">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
              <span>Air-gapped</span>
            </div>
          </div>
        </header>

        {/* Content Viewport */}
        <main className="flex-1 overflow-y-auto p-5 md:p-6">
          <div className="max-w-6xl mx-auto">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
