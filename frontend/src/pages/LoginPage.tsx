import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { User, Lock, Mail, ArrowRight } from "lucide-react";
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
      setError(err instanceof ApiError ? err.message : "Authentication failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-[var(--bg)] px-4">
      <div className="w-full max-w-sm">
        {/* Fortress Plain Wordmark */}
        <div className="text-center mb-6">
          <h1 className="font-semibold text-lg text-[var(--text)] tracking-tight">
            Watch Fortress
          </h1>
          <p className="text-xs text-[var(--text-secondary)] mt-1">
            Vulnerability management console
          </p>
        </div>

        {/* Auth Form Card */}
        <div className="bg-[var(--surface)] border border-[var(--border)] rounded-[5px] p-5">
          <div className="mb-4">
            <h2 className="text-sm font-medium text-[var(--text)]">
              {needsBootstrap ? "Initialize administrator account" : "Sign in"}
            </h2>
            <p className="text-xs text-[var(--text-secondary)] mt-0.5">
              {needsBootstrap
                ? "First-run setup: Create root credentials"
                : "Enter credentials to access the console"}
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-3.5">
            <div>
              <label className="block text-xs font-medium text-[var(--text)] mb-1">
                Username
              </label>
              <div className="relative flex items-center">
                <User size={13} className="absolute left-2.5 text-[var(--text-tertiary)] pointer-events-none" />
                <Input
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                  placeholder="admin"
                  className="pl-8"
                  autoFocus
                />
              </div>
            </div>

            {needsBootstrap && (
              <div>
                <label className="block text-xs font-medium text-[var(--text)] mb-1">
                  Email (optional)
                </label>
                <div className="relative flex items-center">
                  <Mail size={13} className="absolute left-2.5 text-[var(--text-tertiary)] pointer-events-none" />
                  <Input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="admin@internal.local"
                    className="pl-8"
                  />
                </div>
              </div>
            )}

            <div>
              <label className="block text-xs font-medium text-[var(--text)] mb-1">
                Password
              </label>
              <div className="relative flex items-center">
                <Lock size={13} className="absolute left-2.5 text-[var(--text-tertiary)] pointer-events-none" />
                <Input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  placeholder="••••••••••••"
                  className="pl-8"
                />
              </div>
            </div>

            {error && (
              <div className="text-xs text-[var(--critical)] bg-[var(--critical-dim)] border border-transparent rounded-[4px] px-2.5 py-1.5 font-mono-data">
                {error}
              </div>
            )}

            <div className="pt-1">
              <Button
                type="submit"
                disabled={busy}
                variant="primary"
                className="w-full"
                icon={ArrowRight}
              >
                {busy ? "Authenticating..." : needsBootstrap ? "Create account" : "Sign in"}
              </Button>
            </div>
          </form>
        </div>

        <div className="mt-4 text-center text-[11px] text-[var(--text-tertiary)]">
          Air-gapped operation · Audit logged
        </div>
      </div>
    </div>
  );
}
