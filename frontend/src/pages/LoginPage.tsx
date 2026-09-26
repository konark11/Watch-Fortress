import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ShieldAlert } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { api, ApiError } from "../api/client";
import { Button, Input } from "../components/ui";

export default function LoginPage() {
  const { login, user } = useAuth();
  const navigate = useNavigate();
  const [needsBootstrap, setNeedsBootstrap] = useState<boolean | null>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [email, setEmail] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (user) navigate("/");
  }, [user, navigate]);

  useEffect(() => {
    api
      .get<{ needs_bootstrap_admin: boolean }>("/health")
      .then((h) => setNeedsBootstrap(h.needs_bootstrap_admin))
      .catch(() => setNeedsBootstrap(false));
  }, []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      if (needsBootstrap) {
        await api.post("/auth/bootstrap-admin", { username, password, email, role: "administrator" });
      }
      await login(username, password);
      navigate("/");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-[var(--bg)] px-4">
      <div className="w-full max-w-sm">
        <div className="flex flex-col items-center mb-8">
          <div className="w-12 h-12 rounded-xl bg-[var(--brand-dim)] flex items-center justify-center mb-3">
            <ShieldAlert size={24} className="text-[var(--brand)]" />
          </div>
          <div className="font-bold text-lg">Watch Fortress</div>
          <div className="text-xs text-[var(--text-dim)] uppercase tracking-wider mt-1">
            {needsBootstrap ? "Create the administrator account" : "Sign in to continue"}
          </div>
        </div>

        <form onSubmit={handleSubmit} className="bg-[var(--surface)] border border-[var(--border)] rounded-xl p-6 space-y-4">
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1.5">Username</label>
            <Input value={username} onChange={(e) => setUsername(e.target.value)} required className="w-full" autoFocus />
          </div>
          {needsBootstrap && (
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1.5">Email (optional)</label>
              <Input type="email" value={email} onChange={(e) => setEmail(e.target.value)} className="w-full" />
            </div>
          )}
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1.5">Password</label>
            <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required className="w-full" />
          </div>
          {error && <div className="text-xs text-[var(--critical)] bg-[var(--critical-dim)] rounded-lg px-3 py-2">{error}</div>}
          <Button type="submit" disabled={busy} className="w-full">
            {busy ? "Please wait..." : needsBootstrap ? "Create Admin Account" : "Sign In"}
          </Button>
        </form>

        <p className="text-center text-[11px] text-[var(--text-dim)] mt-5">
          Runs fully self-hosted · No external accounts required
        </p>
      </div>
    </div>
  );
}
