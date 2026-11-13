import { useEffect, useState } from "react";
import { Plus, UserX, KeyRound, Users, History } from "lucide-react";
import { api } from "../api/client";
import type { User, AuditEntry } from "../types";
import { Card, Button, Input, Select, EmptyState, SearchInput } from "../components/ui";
import { useAuth } from "../context/AuthContext";

export default function AdminPage() {
  const { hasRole } = useAuth();
  const [tab, setTab] = useState<"users" | "audit">("users");

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--text)]">
            Administration &amp; Audit Trail
          </h1>
          <p className="text-xs text-[var(--text-muted)] mt-1">
            Role-based user provisioning, permission boundaries, and immutable security audit logs
          </p>
        </div>

        <div className="flex gap-1 bg-[var(--surface)] border border-[var(--border)] rounded-lg p-1 w-fit">
          {hasRole("administrator") && (
            <TabButton active={tab === "users"} onClick={() => setTab("users")} icon={Users}>
              User Accounts
            </TabButton>
          )}
          <TabButton active={tab === "audit"} onClick={() => setTab("audit")} icon={History}>
            Audit Log
          </TabButton>
        </div>
      </div>

      {tab === "users" && hasRole("administrator") && <UsersTab />}
      {tab === "audit" && <AuditTab />}
    </div>
  );
}

function TabButton({
  active,
  onClick,
  icon: Icon,
  children,
}: {
  active: boolean;
  onClick: () => void;
  icon?: any;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-2 px-3 py-1.5 rounded-[4px] text-xs font-normal transition-colors cursor-pointer ${
        active
          ? "bg-[var(--surface-2)] text-[var(--text)] font-medium border border-[var(--border-strong)]"
          : "text-[var(--text-secondary)] hover:text-[var(--text)] hover:bg-[var(--surface-hover)] border border-transparent"
      }`}
    >
      {Icon && <Icon size={13} />}
      {children}
    </button>
  );
}

function UsersTab() {
  const [users, setUsers] = useState<User[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("security_analyst");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    load();
  }, []);

  function load() {
    api.get<User[]>("/users").then(setUsers);
  }

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      await api.post("/users", { username, email, password, role });
      setUsername("");
      setEmail("");
      setPassword("");
      setShowForm(false);
      load();
    } catch (err: any) {
      alert(err.message || "Failed to create user");
    } finally {
      setBusy(false);
    }
  }

  async function deactivate(id: number) {
    if (!confirm("Deactivate this user? They will no longer be able to log in.")) return;
    await api.patch(`/users/${id}/deactivate`);
    load();
  }

  async function resetPassword(id: number, uname: string) {
    const newPassword = prompt(
      `Set a new password for "${uname}" (min 8 characters).\nYou must communicate this to the user directly.`,
    );
    if (!newPassword) return;
    if (newPassword.length < 8) {
      alert("Password must be at least 8 characters.");
      return;
    }
    try {
      await api.patch(`/users/${id}/reset-password`, { new_password: newPassword });
      alert(`Password updated for ${uname}.`);
    } catch (err: any) {
      alert(err.message || "Failed to reset password");
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-end">
        <Button
          onClick={() => setShowForm((s) => !s)}
          variant={showForm ? "secondary" : "primary"}
          size="sm"
          icon={Plus}
        >
          {showForm ? "Cancel" : "Create New User"}
        </Button>
      </div>

      {showForm && (
        <Card
          header="Provision New User"
          subtitle="Assign role permissions and initial credentials"
        >
          <form onSubmit={create} className="grid grid-cols-1 md:grid-cols-4 gap-3 items-end">
            <div>
              <label className="text-xs font-semibold text-[var(--text)] block mb-1">
                Username
              </label>
              <Input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                placeholder="analyst1"
                className="w-full text-xs font-mono-data"
              />
            </div>
            <div>
              <label className="text-xs font-semibold text-[var(--text)] block mb-1">
                Email (Optional)
              </label>
              <Input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@internal.corp"
                className="w-full text-xs"
              />
            </div>
            <div>
              <label className="text-xs font-semibold text-[var(--text)] block mb-1">
                Initial Password
              </label>
              <Input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                placeholder="••••••••••••"
                className="w-full text-xs"
              />
            </div>
            <div>
              <label className="text-xs font-semibold text-[var(--text)] block mb-1">
                Role Assignment
              </label>
              <Select
                value={role}
                onChange={(e) => setRole(e.target.value)}
                className="w-full text-xs font-mono-data"
              >
                <option value="administrator">Administrator (Full Access)</option>
                <option value="security_analyst">Security Analyst</option>
                <option value="penetration_tester">Penetration Tester</option>
                <option value="auditor">Auditor (Read-Only)</option>
              </Select>
            </div>
            <div className="md:col-span-4 flex justify-end pt-2">
              <Button type="submit" disabled={busy} variant="primary" size="sm">
                {busy ? "Creating User..." : "Save User Account"}
              </Button>
            </div>
          </form>
        </Card>
      )}

      <Card className="p-0 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm min-w-[700px]">
            <thead>
              <tr className="border-b border-[var(--border)] bg-[var(--surface-2)]/40 font-mono-data uppercase text-xs text-[var(--text-dim)]">
                <th className="text-left px-4 py-3">Operator</th>
                <th className="text-left px-4 py-3">Email</th>
                <th className="text-left px-4 py-3">Assigned Role</th>
                <th className="text-left px-4 py-3">Status</th>
                <th className="text-left px-4 py-3">Created</th>
                <th className="text-right px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border-soft)]">
              {users.map((u) => (
                <tr key={u.id} className="hover:bg-[var(--surface-2)]/30 transition-colors">
                  <td className="px-4 py-3 font-semibold text-[var(--text)] flex items-center gap-2">
                    <div className="w-6 h-6 rounded-md bg-[var(--surface-3)] border border-[var(--border)] flex items-center justify-center font-mono-data text-[10px] text-[var(--brand)]">
                      {u.username.slice(0, 2).toUpperCase()}
                    </div>
                    <span>{u.username}</span>
                  </td>
                  <td className="px-4 py-3 text-xs text-[var(--text-muted)] font-mono-data">
                    {u.email || "—"}
                  </td>
                  <td className="px-4 py-3 text-xs font-mono-data capitalize">
                    <span className="px-2 py-0.5 rounded bg-[var(--surface-2)] border border-[var(--border)] text-[var(--text)]">
                      {u.role.replace("_", " ")}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[10.5px] font-mono-data font-bold uppercase ${
                        u.is_active
                          ? "bg-[var(--brand-dim)] text-[var(--brand)]"
                          : "bg-[var(--critical-dim)] text-[var(--critical)]"
                      }`}
                    >
                      <span
                        className={`w-1.5 h-1.5 rounded-full ${
                          u.is_active ? "bg-[var(--brand)]" : "bg-[var(--critical)]"
                        }`}
                      />
                      {u.is_active ? "Active" : "Deactivated"}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-[var(--text-dim)] font-mono-data">
                    {new Date(u.created_at).toLocaleDateString()}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={() => resetPassword(u.id, u.username)}
                        className="p-1.5 text-[var(--text-dim)] hover:text-[var(--brand)] hover:bg-[var(--surface-2)] rounded transition-colors cursor-pointer"
                        title="Reset user password"
                      >
                        <KeyRound size={15} />
                      </button>
                      {u.is_active && (
                        <button
                          onClick={() => deactivate(u.id)}
                          className="p-1.5 text-[var(--text-dim)] hover:text-[var(--critical)] hover:bg-[var(--critical-dim)] rounded transition-colors cursor-pointer"
                          title="Deactivate account"
                        >
                          <UserX size={15} />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

function AuditTab() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [search, setSearch] = useState("");

  useEffect(() => {
    api.get<{ entries: AuditEntry[] }>("/audit").then((r) => setEntries(r.entries));
  }, []);

  const filtered = entries.filter((e) => {
    if (!search.trim()) return true;
    const term = search.toLowerCase();
    return (
      e.action.toLowerCase().includes(term) ||
      e.username.toLowerCase().includes(term) ||
      e.target.toLowerCase().includes(term) ||
      e.details.toLowerCase().includes(term) ||
      e.ip_address.toLowerCase().includes(term)
    );
  });

  return (
    <div className="space-y-4">
      <div className="w-full sm:w-72">
        <SearchInput
          placeholder="Filter audit logs by action, IP, user..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          onClear={() => setSearch("")}
        />
      </div>

      {entries.length === 0 ? (
        <Card>
          <EmptyState title="No audit entries recorded yet" />
        </Card>
      ) : (
        <Card className="p-0 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm min-w-[840px]">
              <thead>
                <tr className="border-b border-[var(--border)] bg-[var(--surface-2)]/40 font-mono-data uppercase text-xs text-[var(--text-dim)]">
                  <th className="text-left px-4 py-3">Timestamp</th>
                  <th className="text-left px-4 py-3">User</th>
                  <th className="text-left px-4 py-3">Action</th>
                  <th className="text-left px-4 py-3">Target</th>
                  <th className="text-left px-4 py-3">Details</th>
                  <th className="text-right px-4 py-3">Origin IP</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border-soft)]">
                {filtered.map((e) => (
                  <tr key={e.id} className="hover:bg-[var(--surface-2)]/30 transition-colors">
                    <td className="px-4 py-2.5 text-xs text-[var(--text-dim)] font-mono-data whitespace-nowrap">
                      {new Date(e.timestamp).toLocaleString()}
                    </td>
                    <td className="px-4 py-2.5 font-semibold text-xs text-[var(--text)]">
                      {e.username}
                    </td>
                    <td className="px-4 py-2.5 font-mono-data text-xs text-[var(--brand)]">
                      {e.action}
                    </td>
                    <td className="px-4 py-2.5 text-xs text-[var(--text)] font-mono-data">
                      {e.target}
                    </td>
                    <td className="px-4 py-2.5 text-xs text-[var(--text-muted)] max-w-sm truncate">
                      {e.details}
                    </td>
                    <td className="px-4 py-2.5 text-xs text-[var(--text-dim)] font-mono-data text-right">
                      {e.ip_address}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}
