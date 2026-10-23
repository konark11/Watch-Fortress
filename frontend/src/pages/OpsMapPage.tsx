import { useEffect, useMemo, useState } from "react";
import { MapContainer, TileLayer, Polyline, CircleMarker, Marker, Popup, Rectangle, useMapEvents } from "react-leaflet";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import { ShieldOff, Crosshair as CrosshairIcon, Trash2, LocateFixed, MapPin, Server, ArrowUpRight } from "lucide-react";
import { api } from "../api/client";
import { useAuth } from "../context/AuthContext";
import type { OpsMarker, OpsMarkerType, OpsArrow, OpsArrowType, Asset, IOC } from "../types";
import { Card, Button, Input, Select } from "../components/ui";

const GRID_STEP = 10; // degrees - a stylized simplification, not real MGRS
// A dark-themed basemap that still shows real place names (cities,
// countries, borders) - the previous satellite tile layer had no labels
// at all, which made it hard to tell what you'd actually clicked on.
// CARTO's Dark Matter tiles are free, no API key needed, and match a
// dark UI far better than daylight satellite imagery does.
const DARK_TILE_URL = "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png";
const DARK_TILE_ATTRIBUTION = '&copy; <a href="https://carto.com/attributions">CARTO</a> &copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors';

const MARKER_TYPES: { value: OpsMarkerType; label: string; color: string }[] = [
  { value: "threat", label: "Mark Threat", color: "#e2596f" },
  { value: "caution", label: "Mark Caution", color: "#e2955f" },
  { value: "planning", label: "Mark Planning", color: "#5eb8ac" },
  { value: "observation", label: "Add Observation", color: "#7d8590" },
];
const MARKER_COLOR: Record<OpsMarkerType, string> = Object.fromEntries(MARKER_TYPES.map((t) => [t.value, t.color])) as Record<OpsMarkerType, string>;
const ARROW_COLOR: Record<OpsArrowType, string> = { movement: "#5eb8ac", attack: "#e2596f" };

// Spreadsheet-style letter coordinates: columns as uppercase letters
// (A, B, ... Z, AA, AB, ...), rows as a single lowercase letter (a-r
// comfortably covers the 18 rows a 10-degree grid produces). A stylized
// reference scheme, not a real military grid system - the grid is a
// visual aid for orientation, not what markers snap to.
function columnLetters(n: number): string {
  let s = "";
  n += 1;
  while (n > 0) {
    const rem = (n - 1) % 26;
    s = String.fromCharCode(65 + rem) + s;
    n = Math.floor((n - 1) / 26);
  }
  return s;
}
function rowLetter(n: number): string {
  return String.fromCharCode(97 + (n % 26));
}

function cellFor(lat: number, lon: number) {
  const col = Math.min(Math.floor((lon + 180) / GRID_STEP), 360 / GRID_STEP - 1);
  const row = Math.min(Math.floor((90 - lat) / GRID_STEP), 180 / GRID_STEP - 1);
  const lonMin = col * GRID_STEP - 180;
  const latMax = 90 - row * GRID_STEP;
  return {
    gridId: `${columnLetters(col)}${rowLetter(row)}`,
    bounds: [[latMax - GRID_STEP, lonMin], [latMax, lonMin + GRID_STEP]] as [[number, number], [number, number]],
    // The exact point clicked - this is what actually gets saved. The
    // grid cell is only ever used for labeling/reference, never for
    // snapping a marker's real position.
    point: { lat, lon },
  };
}

type Cell = ReturnType<typeof cellFor>;
type LocationMode = "general" | "device" | "arrow";
type DeviceOption = { key: string; kind: "asset" | "ioc"; label: string; lat: number | null; lon: number | null };
type LatLon = { lat: number; lon: number };

function bearingDeg(a: LatLon, b: LatLon): number {
  const toRad = (d: number) => (d * Math.PI) / 180;
  const φ1 = toRad(a.lat), φ2 = toRad(b.lat), Δλ = toRad(b.lon - a.lon);
  const y = Math.sin(Δλ) * Math.cos(φ2);
  const x = Math.cos(φ1) * Math.sin(φ2) - Math.sin(φ1) * Math.cos(φ2) * Math.cos(Δλ);
  return ((Math.atan2(y, x) * 180) / Math.PI + 360) % 360;
}

function arrowheadIcon(color: string, bearing: number) {
  return L.divIcon({
    className: "",
    html: `<div style="width:0;height:0;border-left:6px solid transparent;border-right:6px solid transparent;border-bottom:14px solid ${color};transform:rotate(${bearing}deg);transform-origin:center;filter:drop-shadow(0 0 1px rgba(0,0,0,0.6));"></div>`,
    iconSize: [14, 14],
    iconAnchor: [7, 7],
  });
}

function GridLines() {
  const lines = useMemo(() => {
    const out: [number, number][][] = [];
    for (let lon = -180; lon <= 180; lon += GRID_STEP) out.push([[-90, lon], [90, lon]]);
    for (let lat = -80; lat <= 80; lat += GRID_STEP) out.push([[lat, -180], [lat, 180]]);
    return out;
  }, []);
  return (
    <>
      {lines.map((positions, i) => (
        <Polyline key={i} positions={positions} pathOptions={{ color: "#e4e7ec", weight: 0.6, opacity: 0.28 }} interactive={false} />
      ))}
    </>
  );
}

function CrosshairAndSelect({ active, onClick }: { active: boolean; onClick: (lat: number, lon: number) => void }) {
  const [cursor, setCursor] = useState<LatLon | null>(null);
  const [bounds, setBounds] = useState<{ north: number; south: number; east: number; west: number } | null>(null);

  const map = useMapEvents({
    mousemove(e) {
      if (!active) return;
      setCursor({ lat: e.latlng.lat, lon: e.latlng.lng });
      const b = map.getBounds();
      setBounds({ north: b.getNorth(), south: b.getSouth(), east: b.getEast(), west: b.getWest() });
    },
    mouseout() {
      setCursor(null);
    },
    click(e) {
      if (active) onClick(e.latlng.lat, e.latlng.lng);
    },
  });

  if (!active || !cursor || !bounds) return null;
  const hovered = cellFor(cursor.lat, cursor.lon);

  return (
    <>
      <Polyline positions={[[cursor.lat, bounds.west], [cursor.lat, bounds.east]]} pathOptions={{ color: "#5eb8ac", weight: 1, opacity: 0.8, dashArray: "4 4" }} interactive={false} />
      <Polyline positions={[[bounds.south, cursor.lon], [bounds.north, cursor.lon]]} pathOptions={{ color: "#5eb8ac", weight: 1, opacity: 0.8, dashArray: "4 4" }} interactive={false} />
      <Rectangle bounds={hovered.bounds} pathOptions={{ color: "#5eb8ac", weight: 1, fillOpacity: 0.08 }} interactive={false} />
    </>
  );
}

function ArrowOverlay({ arrow }: { arrow: OpsArrow }) {
  const color = ARROW_COLOR[arrow.arrow_type];
  const a = { lat: arrow.start_lat, lon: arrow.start_lon };
  const b = { lat: arrow.end_lat, lon: arrow.end_lon };
  const icon = useMemo(() => arrowheadIcon(color, bearingDeg(a, b)), [color, arrow.start_lat, arrow.start_lon, arrow.end_lat, arrow.end_lon]);
  return (
    <>
      <Polyline
        positions={[[arrow.start_lat, arrow.start_lon], [arrow.end_lat, arrow.end_lon]]}
        pathOptions={{ color, weight: 2.5, opacity: 0.85, dashArray: arrow.arrow_type === "movement" ? "6 5" : undefined }}
      />
      <Marker position={[arrow.end_lat, arrow.end_lon]} icon={icon}>
        <Popup>
          <div style={{ fontSize: 12, lineHeight: 1.5 }}>
            <strong>{arrow.label || (arrow.arrow_type === "attack" ? "Attack vector" : "Movement")}</strong><br />
            {arrow.arrow_type}<br />
            {arrow.start_lat.toFixed(2)}, {arrow.start_lon.toFixed(2)} → {arrow.end_lat.toFixed(2)}, {arrow.end_lon.toFixed(2)}
            {arrow.notes && <><br />{arrow.notes}</>}
            <br /><span style={{ color: "#888" }}>{arrow.created_by} · {new Date(arrow.created_at).toLocaleString()}</span>
          </div>
        </Popup>
      </Marker>
    </>
  );
}

export default function OpsMapPage() {
  const { hasRole } = useAuth();
  const isAdmin = hasRole("administrator");

  const [markers, setMarkers] = useState<OpsMarker[]>([]);
  const [arrows, setArrows] = useState<OpsArrow[]>([]);
  const [mode, setMode] = useState<LocationMode>("general");
  const [devices, setDevices] = useState<DeviceOption[]>([]);
  const [pendingDevice, setPendingDevice] = useState<DeviceOption | null>(null); // device chosen but still needs a map click (no known coords)
  const [selected, setSelected] = useState<Cell | null>(null);
  const [sourceLabel, setSourceLabel] = useState<string>("General Location");
  const [activeForm, setActiveForm] = useState<OpsMarkerType | null>(null);
  const [title, setTitle] = useState("");
  const [notes, setNotes] = useState("");
  const [busy, setBusy] = useState(false);

  const [arrowStart, setArrowStart] = useState<LatLon | null>(null);
  const [arrowEnd, setArrowEnd] = useState<LatLon | null>(null);
  const [arrowType, setArrowType] = useState<OpsArrowType | null>(null);
  const [arrowLabel, setArrowLabel] = useState("");
  const [arrowNotes, setArrowNotes] = useState("");

  useEffect(() => {
    if (!isAdmin) return;
    load();
    api.get<{ assets: Asset[] }>("/assets").then((r) => {
      setDevices((prev) => [
        ...prev.filter((d) => d.kind !== "asset"),
        ...r.assets.map((a): DeviceOption => ({ key: `asset:${a.id}`, kind: "asset", label: `${a.hostname || a.ip_address} (${a.vulnerability_count} vulns)`, lat: null, lon: null })),
      ]);
    });
    api.get<{ iocs: IOC[] }>("/threat-intel/iocs").then((r) => {
      setDevices((prev) => [
        ...prev.filter((d) => d.kind !== "ioc"),
        ...r.iocs.map((i): DeviceOption => ({ key: `ioc:${i.id}`, kind: "ioc", label: `${i.value}${i.threat_actor ? ` — ${i.threat_actor}` : ""}`, lat: i.latitude, lon: i.longitude })),
      ]);
    });
  }, [isAdmin]);

  function load() {
    api.get<{ markers: OpsMarker[] }>("/ops-map/markers").then((r) => setMarkers(r.markers));
    api.get<{ arrows: OpsArrow[] }>("/ops-map/arrows").then((r) => setArrows(r.arrows));
  }

  function switchMode(next: LocationMode) {
    setMode(next);
    setPendingDevice(null);
    setArrowStart(null); setArrowEnd(null); setArrowType(null);
  }

  function chooseDevice(key: string) {
    const device = devices.find((d) => d.key === key);
    if (!device) return;
    if (device.lat != null && device.lon != null) {
      // Already has real coordinates (a geolocated IOC) - select immediately.
      setSelected(cellFor(device.lat, device.lon));
      setSourceLabel(`${device.kind === "ioc" ? "IOC" : "Asset"}: ${device.label}`);
      setPendingDevice(null);
    } else {
      // An internal asset (or an ungeolocated IOC) has no inherent
      // coordinates - the admin still has to click a point for it.
      setPendingDevice(device);
      setSelected(null);
    }
    setActiveForm(null);
  }

  function handleMapClick(lat: number, lon: number) {
    if (mode === "arrow") {
      if (!arrowStart) setArrowStart({ lat, lon });
      else if (!arrowEnd) setArrowEnd({ lat, lon });
      return;
    }
    const cell = cellFor(lat, lon);
    if (mode === "device" && pendingDevice) {
      setSelected(cell);
      setSourceLabel(`${pendingDevice.kind === "ioc" ? "IOC" : "Asset"}: ${pendingDevice.label}`);
      setPendingDevice(null);
    } else if (mode === "general") {
      setSelected(cell);
      setSourceLabel("General Location");
    }
    setActiveForm(null);
  }

  async function saveMarker(type: OpsMarkerType) {
    if (!selected || !title.trim()) return;
    setBusy(true);
    try {
      await api.post("/ops-map/markers", {
        grid_id: selected.gridId,
        latitude: selected.point.lat,
        longitude: selected.point.lon,
        marker_type: type,
        title: title.trim(),
        notes: notes.trim() || null,
        source_label: sourceLabel,
      });
      setTitle(""); setNotes(""); setActiveForm(null);
      load();
    } finally {
      setBusy(false);
    }
  }

  async function removeMarker(id: number) {
    if (!confirm("Remove this marker?")) return;
    await api.del(`/ops-map/markers/${id}`);
    load();
  }

  async function saveArrow() {
    if (!arrowStart || !arrowEnd || !arrowType) return;
    setBusy(true);
    try {
      await api.post("/ops-map/arrows", {
        arrow_type: arrowType,
        label: arrowLabel.trim() || null,
        start_lat: arrowStart.lat, start_lon: arrowStart.lon,
        end_lat: arrowEnd.lat, end_lon: arrowEnd.lon,
        notes: arrowNotes.trim() || null,
      });
      setArrowStart(null); setArrowEnd(null); setArrowType(null); setArrowLabel(""); setArrowNotes("");
      load();
    } finally {
      setBusy(false);
    }
  }

  async function removeArrow(id: number) {
    if (!confirm("Remove this arrow?")) return;
    await api.del(`/ops-map/arrows/${id}`);
    load();
  }

  if (!isAdmin) {
    return (
      <Card>
        <div className="flex items-center gap-3 text-[var(--text-muted)]">
          <ShieldOff size={20} className="text-[var(--critical)]" />
          <div>
            <div className="text-sm font-semibold text-[var(--text)]">Access restricted</div>
            <div className="text-xs mt-0.5">The Tactical Map is only available to administrators.</div>
          </div>
        </div>
      </Card>
    );
  }

  const cellMarkers = selected ? markers.filter((m) => m.grid_id === selected.gridId) : [];
  const crosshairActive = mode === "general" || mode === "arrow" || !!pendingDevice;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold flex items-center gap-2">
          <CrosshairIcon size={18} className="text-[var(--brand)]" /> Tactical Map
        </h1>
        <p className="text-sm text-[var(--text-muted)] mt-1">
          Admin-only. Every click uses the exact point you select — the grid is a reference overlay, not a snap target.
        </p>
      </div>

      {/* Mode toggle */}
      <Card>
        <div className="flex items-center gap-2 mb-3">
          <div className="flex bg-[var(--surface-2)] rounded-lg p-1">
            <button onClick={() => switchMode("general")} className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md transition-colors ${mode === "general" ? "bg-[var(--brand)] text-[#12151a] font-semibold" : "text-[var(--text-muted)]"}`}>
              <MapPin size={13} /> General Location
            </button>
            <button onClick={() => switchMode("device")} className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md transition-colors ${mode === "device" ? "bg-[var(--brand)] text-[#12151a] font-semibold" : "text-[var(--text-muted)]"}`}>
              <Server size={13} /> Select Device
            </button>
            <button onClick={() => switchMode("arrow")} className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md transition-colors ${mode === "arrow" ? "bg-[var(--brand)] text-[#12151a] font-semibold" : "text-[var(--text-muted)]"}`}>
              <ArrowUpRight size={13} /> Draw Arrow
            </button>
          </div>
        </div>

        {mode === "general" && (
          <p className="text-xs text-[var(--text-dim)]">Move the crosshair on the map and click to select a location.</p>
        )}

        {mode === "device" && (
          <div className="space-y-2">
            <Select onChange={(e) => chooseDevice(e.target.value)} defaultValue="" className="w-full">
              <option value="" disabled>Select an asset or IOC…</option>
              {devices.filter((d) => d.kind === "asset").length > 0 && (
                <optgroup label="Assets">
                  {devices.filter((d) => d.kind === "asset").map((d) => <option key={d.key} value={d.key}>{d.label}</option>)}
                </optgroup>
              )}
              {devices.filter((d) => d.kind === "ioc").length > 0 && (
                <optgroup label="Threat Intel IOCs">
                  {devices.filter((d) => d.kind === "ioc").map((d) => <option key={d.key} value={d.key}>{d.label}{d.lat == null ? " (not geolocated)" : ""}</option>)}
                </optgroup>
              )}
            </Select>
            {pendingDevice && (
              <p className="text-xs text-[var(--brand)]">{pendingDevice.label} has no known coordinates — click a point on the map to place it.</p>
            )}
          </div>
        )}

        {mode === "arrow" && (
          <div className="space-y-2">
            {!arrowStart && <p className="text-xs text-[var(--text-dim)]">Click the starting point of the movement or attack.</p>}
            {arrowStart && !arrowEnd && <p className="text-xs text-[var(--brand)]">Start set — now click the destination point.</p>}
            {arrowStart && arrowEnd && !arrowType && (
              <div className="space-y-1.5">
                <button onClick={() => setArrowType("movement")} className="w-full flex items-center gap-2 text-left text-sm px-3 py-2 rounded-lg bg-[var(--surface-2)] hover:bg-[var(--surface-3)] transition-colors">
                  <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: ARROW_COLOR.movement }} /> Trace Movement
                </button>
                <button onClick={() => setArrowType("attack")} className="w-full flex items-center gap-2 text-left text-sm px-3 py-2 rounded-lg bg-[var(--surface-2)] hover:bg-[var(--surface-3)] transition-colors">
                  <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: ARROW_COLOR.attack }} /> Mark Attack Vector
                </button>
              </div>
            )}
            {arrowType && (
              <div className="space-y-2">
                <Input value={arrowLabel} onChange={(e) => setArrowLabel(e.target.value)} placeholder="Label (optional)" className="w-full" autoFocus />
                <textarea value={arrowNotes} onChange={(e) => setArrowNotes(e.target.value)} placeholder="Notes (optional)" rows={2} className="w-full bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm outline-none focus:border-[var(--brand)]" />
                <div className="flex items-center gap-2">
                  <Button onClick={saveArrow} disabled={busy}>{busy ? "Saving..." : "Save Arrow"}</Button>
                  <Button variant="secondary" onClick={() => { setArrowStart(null); setArrowEnd(null); setArrowType(null); }}>Cancel</Button>
                </div>
              </div>
            )}
            {(arrowStart || arrowEnd) && !arrowType && (
              <button onClick={() => { setArrowStart(null); setArrowEnd(null); }} className="text-xs text-[var(--text-dim)] hover:text-[var(--critical)]">Reset points</button>
            )}
          </div>
        )}
      </Card>

      <div className="grid grid-cols-[1fr_320px] gap-4 items-start">
        <Card className="p-0 overflow-hidden">
          <div style={{ height: 560 }}>
            <MapContainer center={[20, 0]} zoom={2} minZoom={2} worldCopyJump style={{ height: "100%", width: "100%" }}>
              <TileLayer url={DARK_TILE_URL} attribution={DARK_TILE_ATTRIBUTION} subdomains="abcd" maxZoom={19} />
              <GridLines />
              <CrosshairAndSelect active={crosshairActive} onClick={handleMapClick} />

              {arrowStart && !arrowEnd && (
                <CircleMarker center={[arrowStart.lat, arrowStart.lon]} radius={5} pathOptions={{ color: "#fff", weight: 1.5, fillColor: "#5eb8ac", fillOpacity: 0.9 }} />
              )}

              {arrows.map((a) => <ArrowOverlay key={a.id} arrow={a} />)}

              {markers.map((m) => (
                <CircleMarker key={m.id} center={[m.latitude, m.longitude]} radius={7} pathOptions={{ color: "#fff", weight: 1.5, fillColor: MARKER_COLOR[m.marker_type], fillOpacity: 0.9 }}>
                  <Popup>
                    <div style={{ fontSize: 12, lineHeight: 1.5 }}>
                      <strong>{m.title}</strong><br />
                      {m.grid_id} · {m.marker_type}
                      {m.source_label && <><br />{m.source_label}</>}
                      <br />{m.latitude.toFixed(4)}, {m.longitude.toFixed(4)}{m.altitude != null ? ` · ${Math.round(m.altitude)} m elevation` : ""}
                      {m.notes && <><br />{m.notes}</>}
                      <br /><span style={{ color: "#888" }}>{m.created_by} · {new Date(m.created_at).toLocaleString()}</span>
                    </div>
                  </Popup>
                </CircleMarker>
              ))}
            </MapContainer>
          </div>
        </Card>

        <div className="space-y-4">
          <Card>
            <div className="text-xs font-semibold text-[var(--text-muted)] mb-2">Legend</div>
            <div className="space-y-1.5">
              {MARKER_TYPES.map((t) => (
                <div key={t.value} className="flex items-center gap-2 text-xs">
                  <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: t.color }} />
                  <span className="capitalize text-[var(--text-muted)]">{t.value}</span>
                </div>
              ))}
              <div className="flex items-center gap-2 text-xs pt-1 border-t border-[var(--border-soft)] mt-1.5">
                <span className="w-3 h-0.5 shrink-0" style={{ background: ARROW_COLOR.movement }} />
                <span className="text-[var(--text-muted)]">Movement</span>
              </div>
              <div className="flex items-center gap-2 text-xs">
                <span className="w-3 h-0.5 shrink-0" style={{ background: ARROW_COLOR.attack }} />
                <span className="text-[var(--text-muted)]">Attack vector</span>
              </div>
            </div>
            <p className="text-[10px] text-[var(--text-dim)] mt-3">Stylized 10° grid, letter coordinates (e.g. Ca) — not a real MGRS reference · {markers.length} marker{markers.length === 1 ? "" : "s"} · {arrows.length} arrow{arrows.length === 1 ? "" : "s"}</p>
          </Card>

          {arrows.length > 0 && (
            <Card>
              <div className="text-xs font-semibold text-[var(--text-muted)] mb-2">Arrows</div>
              <div className="space-y-1.5">
                {arrows.map((a) => (
                  <div key={a.id} className="flex items-center justify-between text-xs bg-[var(--surface-2)] rounded-lg px-2.5 py-1.5">
                    <span className="flex items-center gap-1.5 min-w-0">
                      <span className="w-2 h-0.5 shrink-0" style={{ background: ARROW_COLOR[a.arrow_type] }} />
                      <span className="truncate">{a.label || (a.arrow_type === "attack" ? "Attack vector" : "Movement")}</span>
                    </span>
                    <button onClick={() => removeArrow(a.id)} className="text-[var(--text-dim)] hover:text-[var(--critical)] shrink-0 ml-2">
                      <Trash2 size={12} />
                    </button>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {mode !== "arrow" && (!selected ? (
            <Card>
              <div className="flex items-center gap-2 text-xs text-[var(--text-dim)]">
                <LocateFixed size={14} /> {mode === "device" && !pendingDevice ? "Select a device above." : "Click a point on the map to select its location."}
              </div>
            </Card>
          ) : (
            <Card>
              <div className="text-sm font-semibold mb-1">{sourceLabel}</div>
              <div className="text-xs text-[var(--text-muted)] space-y-0.5 mb-3">
                <div>Grid: {selected.gridId}</div>
                <div>Coordinates: {selected.point.lat.toFixed(4)}, {selected.point.lon.toFixed(4)}</div>
                <div>Altitude: calculated automatically on save</div>
              </div>

              {!activeForm ? (
                <div className="space-y-1.5">
                  {MARKER_TYPES.map((t) => (
                    <button
                      key={t.value}
                      onClick={() => setActiveForm(t.value)}
                      className="w-full flex items-center gap-2 text-left text-sm px-3 py-2 rounded-lg bg-[var(--surface-2)] hover:bg-[var(--surface-3)] transition-colors"
                    >
                      <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: t.color }} />
                      {t.label}
                    </button>
                  ))}
                </div>
              ) : (
                <div className="space-y-2">
                  <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Title" className="w-full" autoFocus />
                  <textarea
                    value={notes}
                    onChange={(e) => setNotes(e.target.value)}
                    placeholder="Notes (optional)"
                    rows={3}
                    className="w-full bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm outline-none focus:border-[var(--brand)]"
                  />
                  <div className="flex items-center gap-2">
                    <Button onClick={() => saveMarker(activeForm)} disabled={busy || !title.trim()}>{busy ? "Saving..." : "Save"}</Button>
                    <Button variant="secondary" onClick={() => setActiveForm(null)}>Cancel</Button>
                  </div>
                </div>
              )}

              {cellMarkers.length > 0 && (
                <div className="mt-4 pt-3 border-t border-[var(--border-soft)] space-y-1.5">
                  <div className="text-xs font-semibold text-[var(--text-muted)] mb-1">In this cell</div>
                  {cellMarkers.map((m) => (
                    <div key={m.id} className="flex items-center justify-between text-xs bg-[var(--surface-2)] rounded-lg px-2.5 py-1.5">
                      <span className="flex items-center gap-1.5 min-w-0">
                        <span className="w-2 h-2 rounded-full shrink-0" style={{ background: MARKER_COLOR[m.marker_type] }} />
                        <span className="truncate">{m.title}</span>
                      </span>
                      <button onClick={() => removeMarker(m.id)} className="text-[var(--text-dim)] hover:text-[var(--critical)] shrink-0 ml-2">
                        <Trash2 size={12} />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </Card>
          ))}
        </div>
      </div>
    </div>
  );
}
