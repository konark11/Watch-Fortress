import { useEffect, useState } from "react";
import { Plus, UserX, KeyRound } from "lucide-react";
import { api } from "../api/client";
import type { User, AuditEntry } from "../types";
import { Card, Button, Input, Select, EmptyState } from "../components/ui";
import { useAuth } from "../context/AuthContext";

export default function AdminPage() {
  const { hasRole } = useAuth();
  const [tab, setTab] = useState<"users" | "audit">("users");

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold">Administration</h1>
        <p className="text-sm text-[var(--text-muted)] mt-1">User management and audit trail</p>
      </div>

      <div className="flex gap-1 bg-[var(--surface)] border border-[var(--border)] rounded-lg p-1 w-fit">
        {hasRole("administrator") && (
          <TabButton active={tab === "users"} onClick={() => setTab("users")}>Users</TabButton>
        )}
        <TabButton active={tab === "audit"} onClick={() => setTab("audit")}>Audit Log</TabButton>
      </div>

      {tab === "users" && hasRole("administrator") && <UsersTab />}
      {tab === "audit" && <AuditTab />}
    </div>
  );
}

function TabButton({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className={`px-4 py-1.5 rounded-md text-sm font-medium transition-colors ${
        active ? "bg-[var(--brand-dim)] text-[var(--brand)]" : "text-[var(--text-muted)] hover:text-[var(--text)]"
      }`}
    >
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
      setUsername(""); setEmail(""); setPassword("");
      setShowForm(false);
      load();
    } catch (err: any) {
      alert(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function deactivate(id: number) {
    if (!confirm("Deactivate this user?")) return;
    await api.patch(`/users/${id}/deactivate`);
    load();
  }

  async function resetPassword(id: number, username: string) {
    const newPassword = prompt(`Set a new password for "${username}" (min 8 characters).\nYou'll need to share this with them yourself.`);
    if (!newPassword) return;
    if (newPassword.length < 8) {
      alert("Password must be at least 8 characters.");
      return;
    }
    try {
      await api.patch(`/users/${id}/reset-password`, { new_password: newPassword });
      alert(`Password reset for ${username}.`);
    } catch (err: any) {
      alert(err.message);
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-end">
        <Button onClick={() => setShowForm((s) => !s)} className="flex items-center gap-2">
          <Plus size={14} /> New User
        </Button>
      </div>

      {showForm && (
        <Card>
          <form onSubmit={create} className="grid grid-cols-4 gap-3 items-end">
            <div>
              <label className="text-xs text-[var(--text-muted)] block mb-1">Username</label>
              <Input value={username} onChange={(e) => setUsername(e.target.value)} required className="w-full" />
            </div>
            <div>
              <label className="text-xs text-[var(--text-muted)] block mb-1">Email</label>
              <Input type="email" value={email} onChange={(e) => setEmail(e.target.value)} className="w-full" />
            </div>
            <div>
              <label className="text-xs text-[var(--text-muted)] block mb-1">Password</label>
              <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required className="w-full" />
            </div>
            <div>
              <label className="text-xs text-[var(--text-muted)] block mb-1">Role</label>
              <Select value={role} onChange={(e) => setRole(e.target.value)} className="w-full">
                <option value="administrator">Administrator</option>
                <option value="security_analyst">Security Analyst</option>
                <option value="penetration_tester">Penetration Tester</option>
                <option value="auditor">Auditor</option>
              </Select>
            </div>
            <Button type="submit" disabled={busy} className="col-span-4">{busy ? "Creating..." : "Create User"}</Button>
          </form>
        </Card>
      )}

      <Card className="p-0 overflow-hidden">
        <div className="overflow-x-auto">
        <table className="w-full text-sm min-w-[700px]">
          <thead>
            <tr className="border-b border-[var(--border)]">
              {["Username", "Email", "Role", "Status", "Created", ""].map((h) => (
                <th key={h} className="text-left text-xs text-[var(--text-dim)] font-medium px-4 py-3">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id} className="border-b border-[var(--border-soft)] last:border-0">
                <td className="px-4 py-3">{u.username}</td>
                <td className="px-4 py-3 text-[var(--text-muted)]">{u.email || "—"}</td>
                <td className="px-4 py-3 capitalize">{u.role.replace("_", " ")}</td>
                <td className="px-4 py-3">
                  <span className={`text-xs px-2 py-0.5 rounded ${u.is_active ? "bg-[var(--brand-dim)] text-[var(--brand)]" : "bg-[var(--critical-dim)] text-[var(--critical)]"}`}>
                    {u.is_active ? "Active" : "Deactivated"}
                  </span>
                </td>
                <td className="px-4 py-3 text-xs text-[var(--text-dim)]">{new Date(u.created_at).toLocaleDateString()}</td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-3">
                    <button onClick={() => resetPassword(u.id, u.username)} className="text-[var(--text-muted)] hover:text-[var(--brand)]" title="Reset password">
                      <KeyRound size={14} />
                    </button>
                    {u.is_active && (
                      <button onClick={() => deactivate(u.id)} className="text-[var(--text-muted)] hover:text-[var(--critical)]" title="Deactivate">
                        <UserX size={14} />
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

  useEffect(() => {
    api.get<{ entries: AuditEntry[] }>("/audit").then((r) => setEntries(r.entries));
  }, []);

  if (entries.length === 0) return <Card><EmptyState title="No audit entries yet" /></Card>;

  return (
    <Card className="p-0 overflow-hidden">
      <div className="overflow-x-auto">
      <table className="w-full text-sm min-w-[800px]">
        <thead>
          <tr className="border-b border-[var(--border)]">
            {["Time", "User", "Action", "Target", "Details", "IP"].map((h) => (
              <th key={h} className="text-left text-xs text-[var(--text-dim)] font-medium px-4 py-3">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {entries.map((e) => (
            <tr key={e.id} className="border-b border-[var(--border-soft)] last:border-0">
              <td className="px-4 py-3 text-xs text-[var(--text-dim)] font-mono-data whitespace-nowrap">{new Date(e.timestamp).toLocaleString()}</td>
              <td className="px-4 py-3">{e.username}</td>
              <td className="px-4 py-3 font-mono-data text-xs text-[var(--brand)]">{e.action}</td>
              <td className="px-4 py-3 text-xs">{e.target}</td>
              <td className="px-4 py-3 text-xs text-[var(--text-muted)] max-w-xs truncate">{e.details}</td>
              <td className="px-4 py-3 text-xs text-[var(--text-dim)] font-mono-data">{e.ip_address}</td>
            </tr>
          ))}
        </tbody>
      </table>
      </div>
    </Card>
  );
}
