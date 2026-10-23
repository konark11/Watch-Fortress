import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider, useAuth } from "./context/AuthContext";
import AppShell from "./components/AppShell";
import LoginPage from "./pages/LoginPage";
import DashboardPage from "./pages/DashboardPage";
import AssetsPage from "./pages/AssetsPage";
import ScansPage from "./pages/ScansPage";
import VulnerabilitiesPage from "./pages/VulnerabilitiesPage";
import ThreatIntelPage from "./pages/ThreatIntelPage";
import AssistantPage from "./pages/AssistantPage";
import ReportsPage from "./pages/ReportsPage";
import KnowledgePage from "./pages/KnowledgePage";
import SchedulesPage from "./pages/SchedulesPage";
import AdminPage from "./pages/AdminPage";
import ExperimentsPage from "../../experiments/ui/ExperimentsPage";

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center text-[var(--text-muted)] text-sm">
        Loading...
      </div>
    );
  }
  if (!user) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <AppShell />
              </ProtectedRoute>
            }
          >
            <Route index element={<DashboardPage />} />
            <Route path="assets" element={<AssetsPage />} />
            <Route path="scans" element={<ScansPage />} />
            <Route path="vulnerabilities" element={<VulnerabilitiesPage />} />
            <Route path="threat-intel" element={<ThreatIntelPage />} />
            <Route path="assistant" element={<AssistantPage />} />
            <Route path="reports" element={<ReportsPage />} />
            <Route path="knowledge" element={<KnowledgePage />} />
            <Route path="research" element={<ExperimentsPage />} />
            <Route path="schedules" element={<SchedulesPage />} />
            <Route path="admin" element={<AdminPage />} />
          </Route>
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
