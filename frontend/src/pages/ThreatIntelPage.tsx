import { useEffect, useState } from "react";
import { Plus, Globe2, Crosshair, Trash2, Flame, Server, ChevronDown, ChevronRight, Search, Database, AlertTriangle } from "lucide-react";
import { MapContainer, TileLayer, CircleMarker, Popup, useMap } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import { api } from "../api/client";
import type { IOC, MapPoint, IOCType, ExploitPipeline, PipelineTier, Asset, ExploitDBEntry, ExploitScanResult } from "../types";
import { Card, Button, Input, Select, EmptyState, SeverityBadge } from "../components/ui";

const TIER_META: Record<PipelineTier, { label: string; color: string; description: string }> = {
  confirmed_active_targeted: { label: "Active & Targeted", color: "#fb3f5e", description: "Actively exploited in the wild (CISA KEV) AND tied to an IOC you've logged — the strongest signal this pipeline produces." },
  confirmed_active: { label: "Actively Exploited", color: "#fb3f5e", description: "Confirmed active exploitation in the wild, per CISA's Known Exploited Vulnerabilities catalog." },
  adversary_observed: { label: "Adversary-Observed", color: "#fb923c", description: "Not (yet) KEV-listed, but a threat actor/campaign you've logged targets this exact CVE." },
  dormant_exploit: { label: "Dormant Exploit", color: "#fbbf24", description: "A working exploit/PoC exists publicly, but no confirmed active campaign or targeting." },
  no_known_exploit: { label: "No Known Exploit", color: "#64748b", description: "No exploit or adversary-targeting signal beyond the scanner's own severity rating." },
};
const PIPELINE_TIER_ORDER: PipelineTier[] = ["confirmed_active_targeted", "confirmed_active", "adversary_observed", "dormant_exploit", "no_known_exploit"];

const IOC_TYPES: { value: IOCType; label: string }[] = [
  { value: "ip", label: "IP Address" },
  { value: "domain", label: "Domain" },
  { value: "url", label: "URL" },
  { value: "hash", label: "File Hash" },
  { value: "cve", label: "CVE" },
];

const CONFIDENCE_COLOR: Record<string, string> = {
  low: "#38bdf8",
  medium: "#fbbf24",
  high: "#fb3f5e",
};

// Esri's World Imagery layer - free, real satellite/aerial photography,
// no API key required (unlike Mapbox/Google satellite layers, which
// need an account + key the same way the AI assistant's OpenAI mode
// does). Fine for a project like this; a production deployment with
// heavy traffic would want a licensed tile provider instead.
const SATELLITE_TILE_URL = "https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}";
const SATELLITE_ATTRIBUTION = "Tiles &copy; Esri &mdash; Esri, Maxar, Earthstar Geographics, and the GIS User Community";

function FitToPoints({ points }: { points: MapPoint[] }) {
  const map = useMap();
  useEffect(() => {
    if (points.length === 0) return;
    if (points.length === 1) {
      map.setView([points[0].lat, points[0].lon], 4);
    } else {
      map.fitBounds(points.map((p) => [p.lat, p.lon] as [number, number]), { padding: [40, 40] });
    }
  }, [points, map]);
  return null;
}

function ThreatMap({ points }: { points: MapPoint[] }) {
  return (
    <div className="rounded-lg overflow-hidden border border-[var(--border)]" style={{ height: 440 }}>
      <MapContainer center={[20, 0]} zoom={2} minZoom={2} worldCopyJump style={{ height: "100%", width: "100%" }}>
        <TileLayer url={SATELLITE_TILE_URL} attribution={SATELLITE_ATTRIBUTION} />
        <FitToPoints points={points} />
        {points.map((p) => (
          <CircleMarker
            key={p.id}
            center={[p.lat, p.lon]}
            radius={8}
            pathOptions={{
              color: "#ffffff",
              weight: 1.5,
              fillColor: CONFIDENCE_COLOR[p.confidence] || "#6366f1",
              fillOpacity: 0.85,
            }}
          >
            <Popup>
              <div style={{ fontSize: 12, lineHeight: 1.5 }}>
                <strong>{p.value}</strong>
                <br />
                {p.city ? `${p.city}, ${p.country}` : p.country || "Unknown location"}
                {p.threat_actor && <><br />Actor: {p.threat_actor}</>}
                {p.campaign && <><br />Campaign: {p.campaign}</>}
                <br />Confidence: {p.confidence}
              </div>
            </Popup>
          </CircleMarker>
        ))}
      </MapContainer>
    </div>
  );
}

export default function ThreatIntelPage() {
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [points, setPoints] = useState<MapPoint[]>([]);
  const [pipeline, setPipeline] = useState<ExploitPipeline | null>(null);
  const [expandedAssets, setExpandedAssets] = useState<Set<number>>(new Set());
  const [showForm, setShowForm] = useState(false);
  const [busy, setBusy] = useState(false);

  const [edbAvailable, setEdbAvailable] = useState<boolean | null>(null);
  const [edbHint, setEdbHint] = useState<string | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [scanAssetId, setScanAssetId] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<ExploitDBEntry[] | null>(null);
  const [scanResults, setScanResults] = useState<ExploitScanResult[] | null>(null);
  const [expandedResults, setExpandedResults] = useState<Set<number>>(new Set());
  const [edbBusy, setEdbBusy] = useState(false);

  const [iocType, setIocType] = useState<IOCType>("ip");
  const [value, setValue] = useState("");
  const [threatActor, setThreatActor] = useState("");
  const [campaign, setCampaign] = useState("");
  const [source, setSource] = useState("");
  const [relatedCves, setRelatedCves] = useState("");
  const [confidence, setConfidence] = useState("medium");
  const [notes, setNotes] = useState("");

  useEffect(() => {
    load();
    api.get<{ available: boolean; hint: string | null }>("/exploit-db/availability").then((r) => {
      setEdbAvailable(r.available);
      setEdbHint(r.hint);
    });
    api.get<{ assets: Asset[] }>("/assets").then((r) => setAssets(r.assets));
  }, []);

  function load() {
    api.get<{ iocs: IOC[] }>("/threat-intel/iocs").then((r) => setIocs(r.iocs));
    api.get<{ points: MapPoint[] }>("/threat-intel/map").then((r) => setPoints(r.points));
    api.get<ExploitPipeline>("/threat-intel/exploit-pipeline").then(setPipeline);
  }

  async function runSearch(e: React.FormEvent) {
    e.preventDefault();
    if (!searchQuery.trim()) return;
    setEdbBusy(true);
    setSearchResults(null);
    try {
      const r = await api.get<{ exploits: ExploitDBEntry[] }>(`/exploit-db/search?q=${encodeURIComponent(searchQuery.trim())}`);
      setSearchResults(r.exploits);
    } catch (err: any) {
      alert(err.message);
    } finally {
      setEdbBusy(false);
    }
  }

  async function runAssetScan() {
    setEdbBusy(true);
    setScanResults(null);
    try {
      const r = await api.post<{ results: ExploitScanResult[] }>("/exploit-db/scan-assets", {
        asset_id: scanAssetId === "all" ? null : Number(scanAssetId),
      });
      setScanResults(r.results);
    } catch (err: any) {
      alert(err.message);
    } finally {
      setEdbBusy(false);
    }
  }

  function toggleResult(id: number) {
    setExpandedResults((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  function toggleAsset(id: number) {
    setExpandedAssets((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      await api.post("/threat-intel/iocs", {
        ioc_type: iocType,
        value,
        threat_actor: threatActor || null,
        campaign: campaign || null,
        source: source || null,
        related_cves: relatedCves.split(",").map((s) => s.trim()).filter(Boolean),
        confidence,
        notes: notes || null,
      });
      setValue(""); setThreatActor(""); setCampaign(""); setSource(""); setRelatedCves(""); setNotes(""); setConfidence("medium");
      setShowForm(false);
      load();
    } finally {
      setBusy(false);
    }
  }

  async function removeIoc(id: number) {
    if (!confirm("Delete this IOC?")) return;
    await api.del(`/threat-intel/iocs/${id}`);
    load();
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">Threat Intelligence</h1>
          <p className="text-sm text-[var(--text-muted)] mt-1">
            IOCs from past incidents, mapped against your own exposure — and where they were seen from
          </p>
        </div>
        <Button onClick={() => setShowForm((s) => !s)} className="flex items-center gap-2">
          <Plus size={14} /> Log IOC
        </Button>
      </div>

      {showForm && (
        <Card>
          <form onSubmit={create} className="space-y-3">
            <div className="grid grid-cols-3 gap-3">
              <div>
                <label className="text-xs text-[var(--text-muted)] block mb-1">IOC Type</label>
                <Select value={iocType} onChange={(e) => setIocType(e.target.value as IOCType)} className="w-full">
                  {IOC_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
                </Select>
              </div>
              <div className="col-span-2">
                <label className="text-xs text-[var(--text-muted)] block mb-1">Value</label>
                <Input
                  value={value}
                  onChange={(e) => setValue(e.target.value)}
                  placeholder={iocType === "ip" ? "203.0.113.42" : iocType === "cve" ? "CVE-2024-3400" : iocType === "hash" ? "sha256 hash" : "example.com"}
                  required
                  className="w-full"
                />
              </div>
            </div>
            <div className="grid grid-cols-3 gap-3">
              <div>
                <label className="text-xs text-[var(--text-muted)] block mb-1">Threat Actor</label>
                <Input value={threatActor} onChange={(e) => setThreatActor(e.target.value)} placeholder="e.g. APT29" className="w-full" />
              </div>
              <div>
                <label className="text-xs text-[var(--text-muted)] block mb-1">Campaign</label>
                <Input value={campaign} onChange={(e) => setCampaign(e.target.value)} placeholder="e.g. Q3 phishing wave" className="w-full" />
              </div>
              <div>
                <label className="text-xs text-[var(--text-muted)] block mb-1">Confidence</label>
                <Select value={confidence} onChange={(e) => setConfidence(e.target.value)} className="w-full">
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                </Select>
              </div>
            </div>
            <div>
              <label className="text-xs text-[var(--text-muted)] block mb-1">Source / Encounter</label>
              <Input value={source} onChange={(e) => setSource(e.target.value)} placeholder="e.g. Incident #4821 — phishing campaign, July 2026" className="w-full" />
            </div>
            <div>
              <label className="text-xs text-[var(--text-muted)] block mb-1">Related CVEs (comma-separated)</label>
              <Input value={relatedCves} onChange={(e) => setRelatedCves(e.target.value)} placeholder="CVE-2024-3400, CVE-2017-5638" className="w-full" />
            </div>
            <div>
              <label className="text-xs text-[var(--text-muted)] block mb-1">Notes</label>
              <textarea
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                rows={2}
                className="w-full bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm outline-none focus:border-[var(--brand)]"
              />
            </div>
            <Button type="submit" disabled={busy}>{busy ? "Saving..." : "Save IOC"}</Button>
          </form>
        </Card>
      )}

      {/* Exploit pipeline — overall */}
      <Card>
        <div className="flex items-center gap-2 mb-1">
          <Flame size={16} className="text-[var(--critical)]" />
          <h2 className="text-sm font-semibold">Exploit Pipeline</h2>
        </div>
        <p className="text-xs text-[var(--text-muted)] mb-4">
          Every vulnerability your scans found, ranked by whether an exploit is actually active or dormant in the wild — and whether an adversary you've actually logged is known to target it.
        </p>
        {!pipeline ? (
          <div className="text-xs text-[var(--text-dim)]">Loading…</div>
        ) : (
          <div className="grid grid-cols-5 gap-3">
            {PIPELINE_TIER_ORDER.map((tier) => {
              const meta = TIER_META[tier];
              const count = pipeline.overall.tier_counts[tier] ?? 0;
              return (
                <div key={tier} className="bg-[var(--surface-2)] rounded-lg p-3 border-l-2" style={{ borderLeftColor: meta.color }} title={meta.description}>
                  <div className="text-2xl font-bold" style={{ color: meta.color }}>{count}</div>
                  <div className="text-[11px] text-[var(--text-muted)] mt-1 leading-tight">{meta.label}</div>
                </div>
              );
            })}
          </div>
        )}
      </Card>

      {/* Exploit pipeline — per asset */}
      <Card>
        <div className="flex items-center gap-2 mb-3">
          <Server size={16} className="text-[var(--text-muted)]" />
          <h2 className="text-sm font-semibold">By Asset</h2>
          {pipeline && <span className="text-xs text-[var(--text-dim)]">— {pipeline.overall.assets_affected} asset{pipeline.overall.assets_affected === 1 ? "" : "s"} carry a flagged vulnerability</span>}
        </div>
        {!pipeline || pipeline.assets.length === 0 ? (
          <div className="text-xs text-[var(--text-dim)]">
            No assets currently carry a vulnerability with a known exploit or adversary link. Run/import a scan and log IOCs with related CVEs to populate this view.
          </div>
        ) : (
          <div className="space-y-2">
            {pipeline.assets.map((a) => {
              const expanded = expandedAssets.has(a.asset_id);
              const worstTier = a.vulnerabilities[0]?.tier;
              return (
                <div key={a.asset_id} className="bg-[var(--surface-2)] rounded-lg overflow-hidden">
                  <button onClick={() => toggleAsset(a.asset_id)} className="w-full flex items-center justify-between px-3 py-2.5 text-left">
                    <div className="flex items-center gap-2 min-w-0">
                      {expanded ? <ChevronDown size={14} className="shrink-0 text-[var(--text-dim)]" /> : <ChevronRight size={14} className="shrink-0 text-[var(--text-dim)]" />}
                      <span className="text-sm font-medium truncate">{a.hostname || a.ip_address}</span>
                      {a.hostname && <span className="text-xs text-[var(--text-dim)] truncate">({a.ip_address})</span>}
                    </div>
                    <div className="flex items-center gap-3 shrink-0">
                      <span className="text-xs text-[var(--text-muted)]">{a.vulnerabilities.length} flagged</span>
                      {worstTier && (
                        <span className="text-[10px] uppercase tracking-wide font-semibold px-2 py-0.5 rounded" style={{ color: TIER_META[worstTier].color, background: `${TIER_META[worstTier].color}22` }}>
                          {TIER_META[worstTier].label}
                        </span>
                      )}
                    </div>
                  </button>
                  {expanded && (
                    <div className="px-3 pb-3 space-y-2">
                      {a.vulnerabilities.map((v) => (
                        <div key={v.vulnerability_id} className="bg-[var(--surface)] rounded-lg p-3">
                          <div className="flex items-center justify-between gap-3">
                            <div className="min-w-0">
                              <div className="text-sm font-medium truncate">{v.title}</div>
                              <div className="text-xs text-[var(--text-muted)] mt-0.5">{v.cve_ids.join(", ") || "No CVE"}</div>
                            </div>
                            <div className="flex items-center gap-2 shrink-0">
                              <SeverityBadge severity={v.severity} />
                              <span className="text-[10px] uppercase tracking-wide font-semibold px-2 py-0.5 rounded" style={{ color: TIER_META[v.tier].color, background: `${TIER_META[v.tier].color}22` }}>
                                {TIER_META[v.tier].label}
                              </span>
                            </div>
                          </div>
                          {v.matched_iocs.length > 0 && (
                            <div className="mt-2 flex flex-wrap gap-1.5">
                              {v.matched_iocs.map((m) => (
                                <span key={m.ioc_id} className="text-[10px] bg-[var(--surface-2)] text-[var(--text-muted)] rounded-full px-2 py-0.5">
                                  {m.threat_actor || m.value} · {m.matched_cve}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </Card>

      {/* Exploit database (searchsploit) */}
      <Card>
        <div className="flex items-center gap-2 mb-1">
          <Database size={16} className="text-[var(--brand)]" />
          <h2 className="text-sm font-semibold">Exploit Database</h2>
        </div>
        <p className="text-xs text-[var(--text-muted)] mb-4">
          Checks the local Exploit-DB mirror (searchsploit) for real published exploits — the same lookup as running it from the terminal yourself, just fed from your scan data.
        </p>

        {edbAvailable === false && (
          <div className="flex items-start gap-2 bg-[var(--critical-dim)] text-[var(--critical)] rounded-lg p-3 text-xs mb-4">
            <AlertTriangle size={14} className="shrink-0 mt-0.5" />
            <span>{edbHint || "searchsploit is not installed on this system."}</span>
          </div>
        )}

        {/* Manual search */}
        <form onSubmit={runSearch} className="flex items-center gap-2 mb-4">
          <Input
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by CVE (CVE-2024-3400) or keyword (e.g. wordpress)"
            className="flex-1"
            disabled={edbAvailable === false}
          />
          <Button type="submit" disabled={edbBusy || edbAvailable === false} className="flex items-center gap-1.5">
            <Search size={14} /> Search
          </Button>
        </form>
        {searchResults && (
          <div className="space-y-1.5 mb-4">
            {searchResults.length === 0 ? (
              <div className="text-xs text-[var(--text-dim)]">No exploits found for that query.</div>
            ) : (
              searchResults.map((e, i) => (
                <div key={i} className="bg-[var(--surface-2)] rounded-lg px-3 py-2 text-xs">
                  <div className="font-medium text-[var(--text)]">{e.title || "Untitled"}</div>
                  <div className="text-[var(--text-dim)] mt-0.5">
                    EDB-ID {e.edb_id || "?"} · {e.type || "unknown"} · {e.platform || "unknown"} · {e.date || "undated"}{e.verified ? " · verified" : ""}
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        <div className="border-t border-[var(--border-soft)] pt-4">
          <div className="text-xs font-semibold text-[var(--text-muted)] mb-2">Scan CVEs from your own assets</div>
          <div className="flex items-center gap-2">
            <Select value={scanAssetId} onChange={(e) => setScanAssetId(e.target.value)} className="flex-1">
              <option value="all">All Assets</option>
              {assets.map((a) => (
                <option key={a.id} value={a.id}>{a.hostname || a.ip_address} ({a.vulnerability_count} vulns)</option>
              ))}
            </Select>
            <Button onClick={runAssetScan} disabled={edbBusy || edbAvailable === false} className="flex items-center gap-1.5 whitespace-nowrap">
              <Search size={14} /> {edbBusy ? "Scanning..." : "Run Scan"}
            </Button>
          </div>

          {scanResults && (
            <div className="mt-3 space-y-2">
              {scanResults.length === 0 ? (
                <div className="text-xs text-[var(--text-dim)]">No CVEs in this scope had a match in the local Exploit-DB mirror.</div>
              ) : (
                scanResults.map((r, i) => {
                  const expanded = expandedResults.has(i);
                  return (
                    <div key={i} className="bg-[var(--surface-2)] rounded-lg overflow-hidden">
                      <button onClick={() => toggleResult(i)} className="w-full flex items-center justify-between px-3 py-2.5 text-left">
                        <div className="flex items-center gap-2 min-w-0">
                          {expanded ? <ChevronDown size={13} className="shrink-0 text-[var(--text-dim)]" /> : <ChevronRight size={13} className="shrink-0 text-[var(--text-dim)]" />}
                          <span className="text-sm font-medium truncate">{r.vulnerability_title}</span>
                          <span className="text-xs text-[var(--text-dim)] shrink-0">{r.cve}</span>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <SeverityBadge severity={r.severity} />
                          <span
                            className="text-[10px] uppercase tracking-wide font-semibold px-2 py-0.5 rounded"
                            style={{ color: r.maturity === "active" ? "#fb3f5e" : "#fbbf24", background: r.maturity === "active" ? "#fb3f5e22" : "#fbbf2422" }}
                          >
                            {r.maturity === "active" ? "Active (KEV)" : "Dormant"}
                          </span>
                          <span className="text-xs text-[var(--text-muted)]">{r.exploit_count} exploit{r.exploit_count === 1 ? "" : "s"}</span>
                        </div>
                      </button>
                      {expanded && (
                        <div className="px-3 pb-3 space-y-1.5">
                          {r.exploits.map((e, ei) => (
                            <div key={ei} className="bg-[var(--surface)] rounded-lg px-3 py-2 text-xs">
                              <div className="font-medium text-[var(--text)]">{e.title || "Untitled"}</div>
                              <div className="text-[var(--text-dim)] mt-0.5">
                                EDB-ID {e.edb_id || "?"} · {e.type || "unknown"} · {e.platform || "unknown"} · {e.date || "undated"}{e.verified ? " · verified" : ""}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          )}
        </div>
      </Card>

      {/* Threat map */}
      <Card>
        <div className="flex items-center gap-2 mb-3">
          <Globe2 size={16} className="text-[var(--brand)]" />
          <h2 className="text-sm font-semibold">IOC Origins</h2>
          <span className="text-xs text-[var(--text-dim)]">— {points.length} geolocated IP{points.length === 1 ? "" : "s"}</span>
        </div>
        {points.length === 0 ? (
          <div className="text-xs text-[var(--text-dim)] mb-2">No geolocated IOCs yet — log an IP-type IOC to see it plotted here.</div>
        ) : null}
        <ThreatMap points={points} />
        <p className="text-[10px] text-[var(--text-dim)] mt-2">Satellite imagery via Esri · marker color reflects confidence · click a marker for details</p>
      </Card>

      {/* IOC log */}
      <Card>
        <div className="flex items-center gap-2 mb-3">
          <Crosshair size={16} className="text-[var(--text-muted)]" />
          <h2 className="text-sm font-semibold">IOC Log</h2>
        </div>
        {iocs.length === 0 ? (
          <EmptyState title="No IOCs logged yet" hint="Log indicators from past incidents to start correlating them against your own exposure." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-[var(--text-muted)] border-b border-[var(--border)]">
                  <th className="py-2 pr-4">Type</th>
                  <th className="py-2 pr-4">Value</th>
                  <th className="py-2 pr-4">Threat Actor</th>
                  <th className="py-2 pr-4">Related CVEs</th>
                  <th className="py-2 pr-4">Confidence</th>
                  <th className="py-2 pr-4">Logged</th>
                  <th className="py-2"></th>
                </tr>
              </thead>
              <tbody>
                {iocs.map((i) => (
                  <tr key={i.id} className="border-b border-[var(--border-soft)]">
                    <td className="py-2 pr-4 uppercase text-xs text-[var(--text-muted)]">{i.ioc_type}</td>
                    <td className="py-2 pr-4 font-mono-data">{i.value}</td>
                    <td className="py-2 pr-4">{i.threat_actor || "—"}</td>
                    <td className="py-2 pr-4 text-xs">{i.related_cves.length > 0 ? i.related_cves.join(", ") : "—"}</td>
                    <td className="py-2 pr-4 capitalize" style={{ color: CONFIDENCE_COLOR[i.confidence] }}>{i.confidence}</td>
                    <td className="py-2 pr-4 text-xs text-[var(--text-dim)]">{new Date(i.created_at).toLocaleDateString()}</td>
                    <td className="py-2">
                      <button onClick={() => removeIoc(i.id)} className="text-[var(--text-muted)] hover:text-[var(--critical)]">
                        <Trash2 size={14} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
