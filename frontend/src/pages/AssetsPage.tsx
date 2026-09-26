import { useEffect, useState } from "react";
import { Server, Wifi, Shield, Trash2 } from "lucide-react";
import { api } from "../api/client";
import type { Asset } from "../types";
import { Card, EmptyState, SeverityBadge, Select } from "../components/ui";

interface AssetDetail extends Asset {
  ports: { port: number; protocol: string; service: string; product: string; version: string }[];
  vulnerabilities: { id: number; title: string; severity: string; risk_score: number; cve_ids: string[]; status: string }[];
  ssl_certificates: { port: number; subject: string; issuer: string; valid_to: string; self_signed: boolean }[];
}

export default function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [selected, setSelected] = useState<AssetDetail | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    load();
  }, []);

  function load() {
    setLoading(true);
    api
      .get<{ assets: Asset[] }>("/assets")
      .then((r) => setAssets(r.assets))
      .finally(() => setLoading(false));
  }

  function openAsset(id: number) {
    api.get<AssetDetail>(`/assets/${id}`).then(setSelected);
  }

  async function updateCriticality(id: number, criticality: string) {
    await api.patch(`/assets/${id}`, { criticality });
    load();
    if (selected?.id === id) openAsset(id);
  }

  async function removeAsset(id: number) {
    if (!confirm("Delete this asset? Its ports, certificates, and correlated vulnerabilities will be removed too. Raw scan history is kept.")) return;
    await api.del(`/assets/${id}`);
    setSelected(null);
    load();
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold">Asset Inventory</h1>
        <p className="text-sm text-[var(--text-muted)] mt-1">Hosts, ports, services, and OS fingerprints discovered across all scans</p>
      </div>

      {loading ? (
        <div className="text-[var(--text-muted)]">Loading...</div>
      ) : assets.length === 0 ? (
        <Card><EmptyState title="No assets discovered yet" hint="Launch or import a scan to populate the asset inventory." /></Card>
      ) : (
        <div className="grid grid-cols-3 gap-4">
          {assets.map((a) => (
            <button
              key={a.id}
              onClick={() => openAsset(a.id)}
              className="text-left bg-[var(--surface)] border border-[var(--border)] rounded-xl p-4 hover:border-[var(--brand)] transition-colors"
            >
              <div className="flex items-start justify-between mb-2">
                <div className="flex items-center gap-2">
                  <Server size={16} className="text-[var(--text-muted)]" />
                  <span className="font-mono-data font-semibold text-sm">{a.ip_address}</span>
                </div>
                {a.internet_exposed && <Wifi size={14} className="text-[var(--high)]" />}
              </div>
              {a.hostname && <div className="text-xs text-[var(--text-muted)] mb-1 truncate">{a.hostname}</div>}
              {a.os_name && <div className="text-xs text-[var(--text-dim)] mb-3 truncate">{a.os_name}</div>}
              <div className="flex items-center justify-between text-xs">
                <span className="text-[var(--text-muted)]">{a.vulnerability_count} vulns · {a.port_count} ports</span>
                <span className="capitalize px-1.5 py-0.5 rounded bg-[var(--surface-2)] text-[var(--text-muted)]">{a.criticality}</span>
              </div>
              {a.max_risk_score > 0 && (
                <div className="mt-2 h-1.5 rounded-full bg-[var(--surface-2)] overflow-hidden">
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${a.max_risk_score}%`,
                      background: a.max_risk_score >= 80 ? "var(--critical)" : a.max_risk_score >= 60 ? "var(--high)" : "var(--brand)",
                    }}
                  />
                </div>
              )}
            </button>
          ))}
        </div>
      )}

      {selected && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-end z-50" onClick={() => setSelected(null)}>
          <div
            className="bg-[var(--surface)] border-l border-[var(--border)] w-[520px] h-full overflow-y-auto p-6"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Server size={18} className="text-[var(--brand)]" />
                <span className="font-mono-data font-bold text-lg">{selected.ip_address}</span>
              </div>
              <div className="flex items-center gap-3">
                <button onClick={() => removeAsset(selected.id)} className="text-[var(--text-muted)] hover:text-[var(--critical)]" title="Delete asset">
                  <Trash2 size={16} />
                </button>
                <button onClick={() => setSelected(null)} className="text-[var(--text-muted)] hover:text-[var(--text)]">✕</button>
              </div>
            </div>
            {selected.hostname && <div className="text-sm text-[var(--text-muted)]">{selected.hostname}</div>}
            {selected.os_name && <div className="text-sm text-[var(--text-dim)] mb-4">{selected.os_name}</div>}

            <div className="mb-5">
              <label className="text-xs text-[var(--text-muted)] block mb-1">Asset Criticality</label>
              <Select value={selected.criticality} onChange={(e) => updateCriticality(selected.id, e.target.value)}>
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </Select>
            </div>

            <h4 className="text-xs uppercase tracking-wide text-[var(--text-muted)] mb-2 mt-6">Open Ports & Services ({selected.ports.length})</h4>
            <div className="space-y-1.5 mb-6">
              {selected.ports.map((p, i) => (
                <div key={i} className="flex items-center justify-between bg-[var(--surface-2)] rounded-lg px-3 py-2 text-sm">
                  <span className="font-mono-data">{p.port}/{p.protocol}</span>
                  <span className="text-[var(--text-muted)]">{p.service} {p.product} {p.version}</span>
                </div>
              ))}
              {selected.ports.length === 0 && <div className="text-xs text-[var(--text-dim)]">No open ports recorded.</div>}
            </div>

            {selected.ssl_certificates.length > 0 && (
              <>
                <h4 className="text-xs uppercase tracking-wide text-[var(--text-muted)] mb-2">SSL Certificates</h4>
                <div className="space-y-1.5 mb-6">
                  {selected.ssl_certificates.map((c, i) => (
                    <div key={i} className="bg-[var(--surface-2)] rounded-lg px-3 py-2 text-xs">
                      <div className="flex items-center gap-2">
                        <Shield size={12} className={c.self_signed ? "text-[var(--high)]" : "text-[var(--brand)]"} />
                        <span>Port {c.port}: {c.subject || "unknown subject"}</span>
                      </div>
                      {c.self_signed && <div className="text-[var(--high)] mt-1">Self-signed certificate</div>}
                    </div>
                  ))}
                </div>
              </>
            )}

            <h4 className="text-xs uppercase tracking-wide text-[var(--text-muted)] mb-2">Vulnerabilities ({selected.vulnerabilities.length})</h4>
            <div className="space-y-2">
              {selected.vulnerabilities.map((v) => (
                <div key={v.id} className="bg-[var(--surface-2)] rounded-lg px-3 py-2.5">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm font-medium">{v.title}</span>
                    <SeverityBadge severity={v.severity} />
                  </div>
                  <div className="text-xs text-[var(--text-muted)]">
                    Risk {v.risk_score} {v.cve_ids.length > 0 && `· ${v.cve_ids.join(", ")}`}
                  </div>
                </div>
              ))}
              {selected.vulnerabilities.length === 0 && <div className="text-xs text-[var(--text-dim)]">No vulnerabilities found on this asset.</div>}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
