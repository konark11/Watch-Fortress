import { useEffect, useState } from "react";
import {
  Plus,
  Trash2,
  ChevronDown,
  ChevronRight,
  Search,
  AlertTriangle,
} from "lucide-react";
import { MapContainer, TileLayer, CircleMarker, Popup, useMap } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import { api } from "../api/client";
import type {
  IOC,
  MapPoint,
  IOCType,
  ExploitPipeline,
  PipelineTier,
  Asset,
  ExploitDBEntry,
  ExploitScanResult,
} from "../types";
import { Card, Button, Input, Select, EmptyState, SeverityBadge } from "../components/ui";

const TIER_META: Record<PipelineTier, { label: string; color: string; description: string }> = {
  confirmed_active_targeted: {
    label: "Active & Targeted",
    color: "#f43f5e",
    description: "Actively exploited in the wild (CISA KEV) AND tied to a logged incident IOC.",
  },
  confirmed_active: {
    label: "Actively Exploited",
    color: "#f43f5e",
    description: "Confirmed active exploitation in the wild, cataloged in CISA KEV.",
  },
  adversary_observed: {
    label: "Adversary-Observed",
    color: "#f97316",
    description: "A threat actor/campaign targets this CVE, though not yet KEV-cataloged.",
  },
  dormant_exploit: {
    label: "Dormant PoC",
    color: "#f59e0b",
    description: "A functional exploit or PoC exists publicly, without confirmed wild campaign targeting.",
  },
  no_known_exploit: {
    label: "Unexploited",
    color: "#94a3b8",
    description: "No public exploit or adversary-targeting signal detected.",
  },
};
const PIPELINE_TIER_ORDER: PipelineTier[] = [
  "confirmed_active_targeted",
  "confirmed_active",
  "adversary_observed",
  "dormant_exploit",
  "no_known_exploit",
];

const IOC_TYPES: { value: IOCType; label: string }[] = [
  { value: "ip", label: "IP Address" },
  { value: "domain", label: "Domain" },
  { value: "url", label: "URL" },
  { value: "hash", label: "File Hash" },
  { value: "cve", label: "CVE Identifier" },
];

const CONFIDENCE_COLOR: Record<string, string> = {
  low: "#38bdf8",
  medium: "#f59e0b",
  high: "#f43f5e",
};

const SATELLITE_TILE_URL = "https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}";
const SATELLITE_ATTRIBUTION = "Tiles &copy; Esri &mdash; Maxar, Earthstar Geographics";

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
    <div className="rounded-[5px] overflow-hidden border border-[var(--border)]" style={{ height: 420 }}>
      <MapContainer center={[20, 0]} zoom={2} minZoom={2} worldCopyJump style={{ height: "100%", width: "100%" }}>
        <TileLayer url={SATELLITE_TILE_URL} attribution={SATELLITE_ATTRIBUTION} />
        <FitToPoints points={points} />
        {points.map((p) => (
          <CircleMarker
            key={p.id}
            center={[p.lat, p.lon]}
            radius={7}
            pathOptions={{
              color: "#ffffff",
              weight: 1.5,
              fillColor: CONFIDENCE_COLOR[p.confidence] || "#6366f1",
              fillOpacity: 0.9,
            }}
          >
            <Popup>
              <div className="font-mono-data text-xs leading-relaxed text-[#121318]">
                <strong>{p.value}</strong>
                <br />
                {p.city ? `${p.city}, ${p.country}` : p.country || "Geolocated Point"}
                {p.threat_actor && (
                  <>
                    <br />
                    Actor: <strong>{p.threat_actor}</strong>
                  </>
                )}
                {p.campaign && (
                  <>
                    <br />
                    Campaign: {p.campaign}
                  </>
                )}
                <br />
                Confidence: <strong className="uppercase">{p.confidence}</strong>
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
      const r = await api.get<{ exploits: ExploitDBEntry[] }>(
        `/exploit-db/search?q=${encodeURIComponent(searchQuery.trim())}`,
      );
      setSearchResults(r.exploits);
    } catch (err: any) {
      alert(err.message || "Exploit search failed");
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
      alert(err.message || "Asset exploit correlation failed");
    } finally {
      setEdbBusy(false);
    }
  }

  function toggleAsset(assetId: number) {
    setExpandedAssets((prev) => {
      const next = new Set(prev);
      if (next.has(assetId)) next.delete(assetId);
      else next.add(assetId);
      return next;
    });
  }

  function toggleResult(index: number) {
    setExpandedResults((prev) => {
      const next = new Set(prev);
      if (next.has(index)) next.delete(index);
      else next.add(index);
      return next;
    });
  }

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const cves = relatedCves
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      await api.post("/threat-intel/iocs", {
        ioc_type: iocType,
        value,
        threat_actor: threatActor || undefined,
        campaign: campaign || undefined,
        source: source || undefined,
        related_cves: cves,
        confidence,
        notes: notes || undefined,
      });
      setValue("");
      setThreatActor("");
      setCampaign("");
      setSource("");
      setRelatedCves("");
      setNotes("");
      setShowForm(false);
      load();
    } catch (err: any) {
      alert(err.message || "Failed to record IOC");
    } finally {
      setBusy(false);
    }
  }

  async function removeIoc(id: number) {
    if (!confirm("Delete this indicator of compromise?")) return;
    await api.del(`/threat-intel/iocs/${id}`);
    load();
  }

  return (
    <div className="space-y-6">
      {/* Title & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--text)]">
            Adversary Threat Intelligence
          </h1>
          <p className="text-xs text-[var(--text-muted)] mt-1">
            Correlate enterprise telemetry against known threat actors, wild exploit campaigns, and geographical IOCs
          </p>
        </div>
        <Button
          onClick={() => setShowForm((s) => !s)}
          variant={showForm ? "secondary" : "primary"}
          size="sm"
          icon={Plus}
        >
          {showForm ? "Cancel" : "Log New Indicator"}
        </Button>
      </div>

      {/* Log IOC Form */}
      {showForm && (
        <Card
          header="Log Indicator of Compromise (IOC)"
          subtitle="Map adversary footprints against discovered CVE exposure vectors"
        >
          <form onSubmit={create} className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div>
                <label className="text-xs font-semibold text-[var(--text)] block mb-1">
                  Indicator Type
                </label>
                <Select
                  value={iocType}
                  onChange={(e) => setIocType(e.target.value as IOCType)}
                  className="w-full text-xs font-mono-data"
                >
                  {IOC_TYPES.map((t) => (
                    <option key={t.value} value={t.value}>
                      {t.label}
                    </option>
                  ))}
                </Select>
              </div>
              <div className="md:col-span-2">
                <label className="text-xs font-semibold text-[var(--text)] block mb-1">
                  Indicator Value
                </label>
                <Input
                  value={value}
                  onChange={(e) => setValue(e.target.value)}
                  placeholder={
                    iocType === "ip"
                      ? "198.51.100.42"
                      : iocType === "cve"
                      ? "CVE-2024-3400"
                      : iocType === "hash"
                      ? "SHA-256 hash"
                      : "c2.adversary.org"
                  }
                  required
                  className="w-full text-xs font-mono-data"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div>
                <label className="text-xs font-semibold text-[var(--text)] block mb-1">
                  Threat Actor / Group
                </label>
                <Input
                  value={threatActor}
                  onChange={(e) => setThreatActor(e.target.value)}
                  placeholder="e.g. APT29 / Midnight Blizzard"
                  className="w-full text-xs"
                />
              </div>
              <div>
                <label className="text-xs font-semibold text-[var(--text)] block mb-1">
                  Campaign Identifier
                </label>
                <Input
                  value={campaign}
                  onChange={(e) => setCampaign(e.target.value)}
                  placeholder="e.g. Q4 Edge Gateway Campaign"
                  className="w-full text-xs"
                />
              </div>
              <div>
                <label className="text-xs font-semibold text-[var(--text)] block mb-1">
                  Analyst Confidence
                </label>
                <Select
                  value={confidence}
                  onChange={(e) => setConfidence(e.target.value)}
                  className="w-full text-xs font-mono-data uppercase font-bold"
                >
                  <option value="low">Low Confidence</option>
                  <option value="medium">Medium Confidence</option>
                  <option value="high">High Confidence</option>
                </Select>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="text-xs font-semibold text-[var(--text)] block mb-1">
                  Source / Encounter Reference
                </label>
                <Input
                  value={source}
                  onChange={(e) => setSource(e.target.value)}
                  placeholder="e.g. SOC Triage Incident #4821"
                  className="w-full text-xs"
                />
              </div>
              <div>
                <label className="text-xs font-semibold text-[var(--text)] block mb-1">
                  Targeted CVEs (comma-separated)
                </label>
                <Input
                  value={relatedCves}
                  onChange={(e) => setRelatedCves(e.target.value)}
                  placeholder="CVE-2024-3400, CVE-2023-46805"
                  className="w-full text-xs font-mono-data"
                />
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <Button type="submit" disabled={busy} variant="primary" size="sm">
                {busy ? "Saving..." : "Record Indicator"}
              </Button>
            </div>
          </form>
        </Card>
      )}

      {/* Exploit Pipeline - Strategic Tiers */}
      <Card
        header="Exploit Maturity Pipeline"
        subtitle="Findings classified by wild exploit maturity and confirmed adversary interest"
      >
        {!pipeline ? (
          <div className="text-xs font-mono-data text-[var(--text-dim)] py-6 animate-pulse">
            Loading exploit maturity metrics...
          </div>
        ) : (
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
            {PIPELINE_TIER_ORDER.map((tier) => {
              const meta = TIER_META[tier];
              const count = pipeline.overall.tier_counts[tier] ?? 0;
              return (
                <div
                  key={tier}
                  className="bg-[var(--surface-2)] border border-[var(--border)] rounded-[5px] p-3 transition-colors hover:border-[var(--border-strong)]"
                  style={{ borderLeft: `3px solid ${meta.color}` }}
                  title={meta.description}
                >
                  <div className="text-2xl font-bold font-mono-data" style={{ color: meta.color }}>
                    {count}
                  </div>
                  <div className="text-xs font-semibold text-[var(--text)] mt-1 truncate">
                    {meta.label}
                  </div>
                  <div className="text-[10px] text-[var(--text-dim)] mt-0.5 leading-snug line-clamp-2">
                    {meta.description}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </Card>

      {/* Exploit pipeline — per asset */}
      <Card
        header="Exploit Exposure by Asset"
        subtitle={
          pipeline
            ? `${pipeline.overall.assets_affected} asset(s) carry a flagged exploit vulnerability`
            : "Active asset exposures"
        }
      >
        {!pipeline || pipeline.assets.length === 0 ? (
          <div className="text-xs font-mono-data text-[var(--text-tertiary)] p-3 bg-[var(--surface-2)] rounded-[5px]">
            No assets currently carry a vulnerability with a known exploit or adversary link.
          </div>
        ) : (
          <div className="space-y-2">
            {pipeline.assets.map((a) => {
              const expanded = expandedAssets.has(a.asset_id);
              const worstTier = a.vulnerabilities[0]?.tier;
              return (
                <div
                  key={a.asset_id}
                  className="bg-[var(--surface-2)] border border-[var(--border)] rounded-[5px] overflow-hidden"
                >
                  <button
                    onClick={() => toggleAsset(a.asset_id)}
                    className="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-[var(--surface-3)] transition-colors cursor-pointer"
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      {expanded ? (
                        <ChevronDown size={14} className="shrink-0 text-[var(--brand)]" />
                      ) : (
                        <ChevronRight size={14} className="shrink-0 text-[var(--text-dim)]" />
                      )}
                      <span className="text-xs font-bold text-[var(--text)] truncate">
                        {a.hostname || a.ip_address}
                      </span>
                      {a.hostname && (
                        <span className="text-xs text-[var(--text-dim)] font-mono-data">
                          ({a.ip_address})
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-3 shrink-0">
                      <span className="text-xs font-mono-data text-[var(--text-muted)]">
                        {a.vulnerabilities.length} flagged
                      </span>
                      {worstTier && (
                        <span
                          className="text-[10px] font-mono-data uppercase font-bold px-2 py-0.5 rounded"
                          style={{
                            color: TIER_META[worstTier].color,
                            background: `${TIER_META[worstTier].color}18`,
                          }}
                        >
                          {TIER_META[worstTier].label}
                        </span>
                      )}
                    </div>
                  </button>
                  {expanded && (
                    <div className="px-4 pb-3 space-y-2 border-t border-[var(--border-soft)] pt-2 bg-[var(--surface)]/50">
                      {a.vulnerabilities.map((v) => (
                        <div key={v.vulnerability_id} className="bg-[var(--surface-2)] rounded-lg p-3">
                          <div className="flex items-center justify-between gap-3">
                            <div className="min-w-0">
                              <div className="text-xs font-bold text-[var(--text)] truncate">
                                {v.title}
                              </div>
                              <div className="text-[11px] font-mono-data text-[var(--text-muted)] mt-0.5">
                                {v.cve_ids.join(", ") || "No CVE"}
                              </div>
                            </div>
                            <div className="flex items-center gap-2 shrink-0">
                              <SeverityBadge severity={v.severity} />
                              <span
                                className="text-[10px] font-mono-data uppercase font-bold px-1.5 py-0.5 rounded"
                                style={{
                                  color: TIER_META[v.tier].color,
                                  background: `${TIER_META[v.tier].color}18`,
                                }}
                              >
                                {TIER_META[v.tier].label}
                              </span>
                            </div>
                          </div>
                          {v.matched_iocs.length > 0 && (
                            <div className="mt-2 flex flex-wrap gap-1.5">
                              {v.matched_iocs.map((m) => (
                                <span
                                  key={m.ioc_id}
                                  className="text-[10px] font-mono-data bg-[var(--surface-3)] text-[var(--text-muted)] rounded px-1.5 py-0.5 border border-[var(--border)]"
                                >
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

      {/* Exploit Database & Searchsploit */}
      <Card
        header="Exploit Database Verification"
        subtitle="Query local offline Exploit-DB (searchsploit) archives for verified weaponized code"
      >
        {edbAvailable === false && (
          <div className="flex items-start gap-2 bg-[var(--surface-2)] border border-[var(--border)] text-[var(--critical)] rounded-[5px] p-3 text-xs font-mono-data mb-4">
            <AlertTriangle size={14} className="shrink-0 mt-0.5" />
            <span>{edbHint || "Searchsploit mirror is not currently mounted."}</span>
          </div>
        )}

        <form onSubmit={runSearch} className="flex gap-2 mb-4">
          <Input
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search Exploit-DB by CVE (e.g. CVE-2024-3400) or software title..."
            className="flex-1 text-xs font-mono-data"
            disabled={edbAvailable === false}
          />
          <Button
            type="submit"
            disabled={edbBusy || edbAvailable === false}
            variant="secondary"
            size="sm"
            icon={Search}
          >
            {edbBusy ? "Searching..." : "Lookup PoC"}
          </Button>
        </form>

        {searchResults && (
          <div className="space-y-2 mb-4">
            {searchResults.length === 0 ? (
              <div className="text-xs font-mono-data text-[var(--text-tertiary)] p-3 bg-[var(--surface-2)] rounded-[5px]">
                No matching weaponized exploits recorded for query.
              </div>
            ) : (
              searchResults.map((e, i) => (
                <div
                  key={i}
                  className="bg-[var(--surface-2)] border border-[var(--border)] rounded-[4px] px-3 py-2 text-xs font-mono-data flex items-center justify-between gap-3"
                >
                  <div className="min-w-0">
                    <span className="font-bold text-[var(--brand)] mr-2">EDB-{e.edb_id || "?"}</span>
                    <span className="text-[var(--text)] font-semibold">{e.title || "Untitled"}</span>
                    <div className="text-[10px] text-[var(--text-dim)] mt-0.5">
                      Platform: {e.platform || "unknown"} · Type: {e.type || "unknown"} · Date: {e.date || "undated"}
                    </div>
                  </div>
                  {e.verified && (
                    <span className="px-1.5 py-0.5 rounded bg-[var(--brand-dim)] text-[var(--brand)] text-[10px] font-bold uppercase shrink-0">
                      Verified
                    </span>
                  )}
                </div>
              ))
            )}
          </div>
        )}

        {/* Scan CVEs from assets */}
        <div className="pt-4 border-t border-[var(--border-soft)]">
          <div className="text-xs font-semibold text-[var(--text)] mb-2">
            Auto-Match Discovered Findings Against Exploit-DB
          </div>
          <div className="flex items-center gap-2">
            <Select
              value={scanAssetId}
              onChange={(e) => setScanAssetId(e.target.value)}
              className="flex-1 text-xs font-mono-data"
            >
              <option value="all">All Discovered Assets ({assets.length})</option>
              {assets.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.hostname || a.ip_address} ({a.vulnerability_count} findings)
                </option>
              ))}
            </Select>
            <Button
              onClick={runAssetScan}
              disabled={edbBusy || edbAvailable === false}
              variant="primary"
              size="sm"
              icon={Search}
            >
              {edbBusy ? "Analyzing..." : "Correlate Exploits"}
            </Button>
          </div>

          {scanResults && (
            <div className="mt-4 space-y-2">
              {scanResults.length === 0 ? (
                <div className="text-xs font-mono-data text-[var(--text-tertiary)] p-3 bg-[var(--surface-2)] rounded-[5px]">
                  No weaponized exploits detected matching the scanned CVE inventory.
                </div>
              ) : (
                scanResults.map((r, i) => {
                  const expanded = expandedResults.has(i);
                  return (
                    <div
                      key={i}
                      className="bg-[var(--surface-2)] border border-[var(--border)] rounded-[5px] overflow-hidden"
                    >
                      <button
                        onClick={() => toggleResult(i)}
                        className="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-[var(--surface-3)] transition-colors cursor-pointer"
                      >
                        <div className="flex items-center gap-2.5 min-w-0">
                          {expanded ? (
                            <ChevronDown size={14} className="shrink-0 text-[var(--brand)]" />
                          ) : (
                            <ChevronRight size={14} className="shrink-0 text-[var(--text-dim)]" />
                          )}
                          <span className="text-xs font-bold text-[var(--text)] truncate">
                            {r.vulnerability_title}
                          </span>
                          <span className="text-xs font-mono-data text-[var(--brand)] shrink-0">
                            {r.cve}
                          </span>
                        </div>
                        <div className="flex items-center gap-2.5 shrink-0">
                          <SeverityBadge severity={r.severity} />
                          <span className="text-xs font-mono-data text-[var(--text-muted)]">
                            <strong className="text-[var(--text)]">{r.exploit_count}</strong> exploit(s)
                          </span>
                        </div>
                      </button>

                      {expanded && (
                        <div className="px-4 pb-3 space-y-2 border-t border-[var(--border-soft)] pt-2 bg-[var(--surface)]/50">
                          {r.exploits.map((e, ei) => (
                            <div
                              key={ei}
                              className="bg-[var(--surface-2)] rounded-lg p-2.5 text-xs font-mono-data"
                            >
                              <div className="font-semibold text-[var(--text)]">{e.title}</div>
                              <div className="text-[10px] text-[var(--text-dim)] mt-0.5">
                                EDB-{e.edb_id} · {e.type} · {e.platform} · {e.date}
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

      {/* Geospatial Threat Map */}
      <Card
        header="Geospatial Threat Origins"
        subtitle={`${points.length} geolocated threat indicator IP coordinate(s)`}
      >
        <ThreatMap points={points} />
        <div className="flex items-center justify-between text-[11px] font-mono-data text-[var(--text-dim)] mt-2.5">
          <span>Esri World Imagery tile basemap · Color indicates confidence</span>
          <span>Click indicator circle for actor and campaign telemetry</span>
        </div>
      </Card>

      {/* Indicators of Compromise Log */}
      <Card
        header="Indicator Log &amp; Correlation Record"
        subtitle="Logged indicators evaluated against active CVE footprint"
      >
        {iocs.length === 0 ? (
          <EmptyState
            title="No threat indicators recorded"
            hint="Record IPs, hashes, or CVEs encountered during incidents to trace recurring threat campaigns."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs font-mono-data">
              <thead>
                <tr className="border-b border-[var(--border)] text-[var(--text-dim)] uppercase">
                  <th className="text-left py-2.5 px-3">Type</th>
                  <th className="text-left py-2.5 px-3">Indicator Value</th>
                  <th className="text-left py-2.5 px-3">Threat Actor</th>
                  <th className="text-left py-2.5 px-3">Related CVEs</th>
                  <th className="text-left py-2.5 px-3">Confidence</th>
                  <th className="text-left py-2.5 px-3">Logged Date</th>
                  <th className="text-right py-2.5 px-3">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border-soft)]">
                {iocs.map((i) => (
                  <tr key={i.id} className="hover:bg-[var(--surface-2)]/30 transition-colors">
                    <td className="py-2.5 px-3 uppercase text-[var(--brand)] font-bold">
                      {i.ioc_type}
                    </td>
                    <td className="py-2.5 px-3 text-[var(--text)] font-semibold">{i.value}</td>
                    <td className="py-2.5 px-3 text-[var(--text-muted)]">{i.threat_actor || "—"}</td>
                    <td className="py-2.5 px-3 text-[var(--text-dim)]">
                      {i.related_cves.length > 0 ? i.related_cves.join(", ") : "—"}
                    </td>
                    <td
                      className="py-2.5 px-3 uppercase font-bold"
                      style={{ color: CONFIDENCE_COLOR[i.confidence] }}
                    >
                      {i.confidence}
                    </td>
                    <td className="py-2.5 px-3 text-[var(--text-dim)]">
                      {new Date(i.created_at).toLocaleDateString()}
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <button
                        onClick={() => removeIoc(i.id)}
                        className="p-1 text-[var(--text-dim)] hover:text-[var(--critical)] rounded transition-colors cursor-pointer"
                        title="Delete Indicator"
                      >
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

      {/* Exploit pipeline — per asset */}
      <Card
        header="Exploit Exposure by Asset"
        subtitle={
          pipeline
            ? `${pipeline.overall.assets_affected} asset(s) carry a flagged exploit vulnerability`
            : "Active asset exposures"
        }
      >
        {!pipeline || pipeline.assets.length === 0 ? (
          <div className="text-xs font-mono-data text-[var(--text-tertiary)] p-3 bg-[var(--surface-2)] rounded-[5px]">
            No assets currently carry a vulnerability with a known exploit or adversary link.
          </div>
        ) : (
          <div className="space-y-2">
            {pipeline.assets.map((a) => {
              const expanded = expandedAssets.has(a.asset_id);
              const worstTier = a.vulnerabilities[0]?.tier;
              return (
                <div
                  key={a.asset_id}
                  className="bg-[var(--surface-2)] border border-[var(--border)] rounded-[5px] overflow-hidden"
                >
                  <button
                    onClick={() => toggleAsset(a.asset_id)}
                    className="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-[var(--surface-3)] transition-colors cursor-pointer"
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      {expanded ? (
                        <ChevronDown size={14} className="shrink-0 text-[var(--brand)]" />
                      ) : (
                        <ChevronRight size={14} className="shrink-0 text-[var(--text-dim)]" />
                      )}
                      <span className="text-xs font-bold text-[var(--text)] truncate">
                        {a.hostname || a.ip_address}
                      </span>
                      {a.hostname && (
                        <span className="text-xs text-[var(--text-dim)] font-mono-data">
                          ({a.ip_address})
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-3 shrink-0">
                      <span className="text-xs font-mono-data text-[var(--text-muted)]">
                        {a.vulnerabilities.length} flagged
                      </span>
                      {worstTier && (
                        <span
                          className="text-[10px] font-mono-data uppercase font-bold px-2 py-0.5 rounded"
                          style={{
                            color: TIER_META[worstTier].color,
                            background: `${TIER_META[worstTier].color}18`,
                          }}
                        >
                          {TIER_META[worstTier].label}
                        </span>
                      )}
                    </div>
                  </button>
                  {expanded && (
                    <div className="px-4 pb-3 space-y-2 border-t border-[var(--border-soft)] pt-2 bg-[var(--surface)]/50">
                      {a.vulnerabilities.map((v) => (
                        <div key={v.vulnerability_id} className="bg-[var(--surface-2)] rounded-lg p-3">
                          <div className="flex items-center justify-between gap-3">
                            <div className="min-w-0">
                              <div className="text-xs font-bold text-[var(--text)] truncate">
                                {v.title}
                              </div>
                              <div className="text-[11px] font-mono-data text-[var(--text-muted)] mt-0.5">
                                {v.cve_ids.join(", ") || "No CVE"}
                              </div>
                            </div>
                            <div className="flex items-center gap-2 shrink-0">
                              <SeverityBadge severity={v.severity} />
                              <span
                                className="text-[10px] font-mono-data uppercase font-bold px-1.5 py-0.5 rounded"
                                style={{
                                  color: TIER_META[v.tier].color,
                                  background: `${TIER_META[v.tier].color}18`,
                                }}
                              >
                                {TIER_META[v.tier].label}
                              </span>
                            </div>
                          </div>
                          {v.matched_iocs.length > 0 && (
                            <div className="mt-2 flex flex-wrap gap-1.5">
                              {v.matched_iocs.map((m) => (
                                <span
                                  key={m.ioc_id}
                                  className="text-[10px] font-mono-data bg-[var(--surface-3)] text-[var(--text-muted)] rounded px-1.5 py-0.5 border border-[var(--border)]"
                                >
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
    </div>
  );
}
