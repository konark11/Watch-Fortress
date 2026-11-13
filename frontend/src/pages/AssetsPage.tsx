import { useEffect, useState } from "react";
import { Server, Wifi, Trash2, Cpu } from "lucide-react";
import { api } from "../api/client";
import type { Asset } from "../types";
import {
  Card,
  EmptyState,
  SeverityBadge,
  Select,
  Drawer,
  SearchInput,
} from "../components/ui";

interface AssetDetail extends Asset {
  ports: { port: number; protocol: string; service: string; product: string; version: string }[];
  vulnerabilities: { id: number; title: string; severity: string; risk_score: number; cve_ids: string[]; status: string }[];
  ssl_certificates: { port: number; subject: string; issuer: string; valid_to: string; self_signed: boolean }[];
}

export default function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [search, setSearch] = useState("");
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
    if (
      !confirm(
        "Delete this asset? Associated open ports and correlated vulnerability links will be removed.",
      )
    )
      return;
    await api.del(`/assets/${id}`);
    setSelected(null);
    load();
  }

  const filteredAssets = assets.filter((a) => {
    if (!search.trim()) return true;
    const term = search.toLowerCase();
    return (
      a.ip_address.toLowerCase().includes(term) ||
      (a.hostname && a.hostname.toLowerCase().includes(term)) ||
      (a.os_name && a.os_name.toLowerCase().includes(term)) ||
      a.criticality.toLowerCase().includes(term)
    );
  });

  return (
    <div className="space-y-4">
      {/* Title & Filter Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-base font-semibold text-[var(--text)]">
            Assets
          </h1>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">
            <span className="font-mono-data text-[var(--text)]">{assets.length}</span> hosts and open network services.
          </p>
        </div>

        <div className="w-full sm:w-64">
          <SearchInput
            placeholder="Search by IP, host, or OS..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onClear={() => setSearch("")}
          />
        </div>
      </div>

      {/* Asset Grid */}
      {loading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 animate-pulse">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="h-36 bg-[var(--surface)] border border-[var(--border)] rounded-[5px]" />
          ))}
        </div>
      ) : filteredAssets.length === 0 ? (
        <Card>
          <EmptyState
            title="No assets found"
            hint={search ? "Try adjusting your search criteria." : "Run a scan or import a report to populate assets."}
          />
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {filteredAssets.map((a) => (
            <button
              key={a.id}
              type="button"
              onClick={() => openAsset(a.id)}
              className="text-left bg-[var(--surface)] border border-[var(--border)] hover:border-[var(--border-strong)] rounded-[5px] p-3.5 transition-colors flex flex-col justify-between cursor-pointer"
            >
              <div>
                <div className="flex items-start justify-between gap-2 mb-1.5">
                  <div className="flex items-center gap-2 min-w-0">
                    <Server size={13} className="text-[var(--text-tertiary)] shrink-0" />
                    <span className="font-mono-data font-medium text-xs text-[var(--text)] truncate">
                      {a.ip_address}
                    </span>
                  </div>

                  {a.internet_exposed && (
                    <span
                      className="inline-flex items-center gap-1 text-[11px] text-[var(--high)] shrink-0"
                      title="Exposed to Public Internet"
                    >
                      <Wifi size={10} /> Public
                    </span>
                  )}
                </div>

                {a.hostname && (
                  <div className="text-xs text-[var(--text-secondary)] mb-1 truncate font-mono-data">
                    {a.hostname}
                  </div>
                )}
                {a.os_name && (
                  <div className="text-[11px] text-[var(--text-tertiary)] mb-2 truncate flex items-center gap-1">
                    <Cpu size={11} className="shrink-0" />
                    <span className="truncate">{a.os_name}</span>
                  </div>
                )}
              </div>

              <div className="pt-2.5 border-t border-[var(--border)]">
                <div className="flex items-center justify-between text-xs font-mono-data mb-1.5">
                  <span className="text-[var(--text-secondary)]">
                    {a.port_count} ports · {a.vulnerability_count} vulns
                  </span>
                  <span className="capitalize text-[11px] text-[var(--text-tertiary)]">
                    {a.criticality}
                  </span>
                </div>

                {a.max_risk_score > 0 ? (
                  <div className="h-1 rounded-full bg-[var(--surface-3)] overflow-hidden">
                    <div
                      className="h-full rounded-full"
                      style={{
                        width: `${Math.min(a.max_risk_score, 100)}%`,
                        background:
                          a.max_risk_score >= 80
                            ? "var(--critical)"
                            : a.max_risk_score >= 60
                            ? "var(--high)"
                            : "var(--accent)",
                      }}
                    />
                  </div>
                ) : (
                  <div className="h-1 rounded-full bg-[var(--surface-2)]" />
                )}
              </div>
            </button>
          ))}
        </div>
      )}

      {/* Asset Detail Drawer */}
      <Drawer
        isOpen={Boolean(selected)}
        onClose={() => setSelected(null)}
        width="560px"
        title={
          <div className="flex items-center justify-between gap-3">
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <Server size={14} className="text-[var(--text-tertiary)]" />
                <span className="font-mono-data font-medium text-sm text-[var(--text)]">
                  {selected?.ip_address}
                </span>
                {selected?.internet_exposed && (
                  <span className="text-[11px] text-[var(--high)]">
                    Public
                  </span>
                )}
              </div>
              {selected?.hostname && (
                <div className="text-xs text-[var(--text-secondary)] font-mono-data mt-0.5 truncate">
                  {selected.hostname}
                </div>
              )}
            </div>

            {selected && (
              <button
                type="button"
                onClick={() => removeAsset(selected.id)}
                className="p-1 text-[var(--text-tertiary)] hover:text-[var(--critical)] rounded transition-colors cursor-pointer"
                title="Delete this asset"
              >
                <Trash2 size={14} />
              </button>
            )}
          </div>
        }
      >
        {selected && (
          <div className="space-y-4 text-xs">
            {/* Criticality */}
            <div className="bg-[var(--surface-2)] border border-[var(--border)] rounded-[5px] p-3 flex items-center justify-between gap-4">
              <div>
                <span className="font-medium text-[var(--text)] block">
                  Asset criticality
                </span>
                <span className="text-[11px] text-[var(--text-tertiary)]">
                  Multiplies risk scoring priority
                </span>
              </div>
              <Select
                value={selected.criticality}
                onChange={(e) => updateCriticality(selected.id, e.target.value)}
                className="w-32 capitalize"
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </Select>
            </div>

            {selected.os_name && (
              <div className="p-2.5 bg-[var(--surface-2)] border border-[var(--border)] rounded-[5px] text-[var(--text-secondary)] flex items-center gap-2 font-mono-data">
                <Cpu size={13} className="text-[var(--text-tertiary)] shrink-0" />
                <span>OS: {selected.os_name}</span>
              </div>
            )}

            {/* Open Ports */}
            <div>
              <div className="font-medium text-[var(--text)] mb-1.5">
                Open ports ({selected.ports.length})
              </div>
              {selected.ports.length === 0 ? (
                <div className="text-[var(--text-tertiary)] p-2.5 bg-[var(--surface-2)] rounded-[5px]">
                  No open network ports recorded.
                </div>
              ) : (
                <div className="space-y-1">
                  {selected.ports.map((p, i) => (
                    <div
                      key={i}
                      className="bg-[var(--surface-2)] border border-[var(--border)] rounded-[4px] px-3 py-1.5 flex items-center justify-between font-mono-data"
                    >
                      <span className="font-medium text-[var(--text)]">
                        {p.port}/{p.protocol}
                      </span>
                      <span className="text-[var(--text-secondary)]">
                        {p.service}{" "}
                        <span className="text-[var(--text-tertiary)]">
                          {p.product} {p.version}
                        </span>
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* SSL Certificates */}
            {selected.ssl_certificates.length > 0 && (
              <div>
                <div className="font-medium text-[var(--text)] mb-1.5">
                  TLS certificates ({selected.ssl_certificates.length})
                </div>
                <div className="space-y-1.5">
                  {selected.ssl_certificates.map((c, i) => (
                    <div
                      key={i}
                      className="bg-[var(--surface-2)] border border-[var(--border)] rounded-[4px] p-2.5 font-mono-data"
                    >
                      <div className="flex items-center justify-between mb-0.5">
                        <span className="font-medium text-[var(--text)]">Port {c.port}</span>
                        <span className="text-[10px] text-[var(--text-tertiary)]">
                          {c.self_signed ? "Self-signed" : "Valid CA"}
                        </span>
                      </div>
                      <div className="text-[var(--text-secondary)] truncate">{c.subject}</div>
                      <div className="text-[10px] text-[var(--text-tertiary)] mt-0.5">
                        Issuer: {c.issuer || "Unknown"} · Valid to: {c.valid_to || "N/A"}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Correlated Vulnerabilities */}
            <div>
              <div className="font-medium text-[var(--text)] mb-1.5">
                Vulnerabilities ({selected.vulnerabilities.length})
              </div>
              {selected.vulnerabilities.length === 0 ? (
                <div className="text-[var(--text-tertiary)] p-2.5 bg-[var(--surface-2)] rounded-[5px]">
                  No active vulnerabilities recorded on this asset.
                </div>
              ) : (
                <div className="space-y-1.5">
                  {selected.vulnerabilities.map((v) => (
                    <div
                      key={v.id}
                      className="bg-[var(--surface-2)] border border-[var(--border)] rounded-[4px] p-2.5"
                    >
                      <div className="flex items-start justify-between gap-2 mb-1">
                        <span className="font-medium text-[var(--text)] leading-snug">
                          {v.title}
                        </span>
                        <SeverityBadge severity={v.severity} />
                      </div>
                      <div className="flex items-center gap-2 font-mono-data text-[11px] text-[var(--text-tertiary)]">
                        <span>Risk: {v.risk_score}</span>
                        {v.cve_ids.length > 0 && (
                          <span>· CVEs: {v.cve_ids.join(", ")}</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
}
