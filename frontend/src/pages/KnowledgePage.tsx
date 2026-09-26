import { useEffect, useState } from "react";
import { Plus, BookOpen, ListChecks, Bug, Wrench, Scale, Lightbulb, X, Trash2 } from "lucide-react";
import { api } from "../api/client";
import type { KnowledgeDoc } from "../types";
import { Card, Button, Input, Select, EmptyState } from "../components/ui";

type FieldType = "textarea" | "steps";
type FieldSchema = { key: string; label: string; type: FieldType; placeholder?: string };

const CATEGORIES = [
  { value: "playbook", label: "Playbook" },
  { value: "vulnerability_writeup", label: "Vulnerability Write-up" },
  { value: "remediation_guide", label: "Remediation Guide" },
  { value: "organization_policy", label: "Organization Policy" },
  { value: "lessons_learned", label: "Lessons Learned" },
];

// What distinguishes each doc type from every other: its own set of
// fields, captured separately instead of one generic textarea. These get
// composed into a single "## Section" formatted string for storage (no
// backend schema change needed) and parsed back out for display.
const CATEGORY_SCHEMAS: Record<string, FieldSchema[]> = {
  playbook: [
    { key: "Objective", label: "Objective", type: "textarea", placeholder: "What this playbook accomplishes and when to use it" },
    { key: "Steps", label: "Steps", type: "steps", placeholder: "e.g. Isolate the affected host from the network" },
  ],
  vulnerability_writeup: [
    { key: "Summary", label: "Summary", type: "textarea", placeholder: "What the vulnerability is, in a sentence or two" },
    { key: "Affected Systems", label: "Affected Systems", type: "textarea", placeholder: "Which assets, services, or software versions are exposed" },
    { key: "Impact", label: "Impact", type: "textarea", placeholder: "What an attacker could actually do with this" },
    { key: "Evidence", label: "Evidence / Technical Details", type: "textarea", placeholder: "Proof-of-concept notes, scan output, request/response samples" },
  ],
  remediation_guide: [
    { key: "Remediation Steps", label: "Remediation Steps", type: "steps", placeholder: "e.g. Apply vendor patch KB123456" },
    { key: "Verification", label: "Verification", type: "textarea", placeholder: "How to confirm the fix actually worked" },
  ],
  organization_policy: [
    { key: "Policy Statement", label: "Policy Statement", type: "textarea", placeholder: "The actual rule/requirement" },
    { key: "Scope", label: "Scope", type: "textarea", placeholder: "Who and what this policy applies to" },
    { key: "Enforcement", label: "Enforcement", type: "textarea", placeholder: "What happens if this isn't followed" },
  ],
  lessons_learned: [
    { key: "What Happened", label: "What Happened", type: "textarea", placeholder: "A factual account of the incident" },
    { key: "Root Cause", label: "Root Cause", type: "textarea", placeholder: "The underlying reason it occurred" },
    { key: "Action Items", label: "Action Items", type: "steps", placeholder: "e.g. Add alerting for this condition" },
  ],
};

const CATEGORY_META: Record<string, { icon: typeof BookOpen; color: string }> = {
  playbook: { icon: ListChecks, color: "text-[var(--brand)]" },
  vulnerability_writeup: { icon: Bug, color: "text-[var(--critical)]" },
  remediation_guide: { icon: Wrench, color: "text-[var(--low)]" },
  organization_policy: { icon: Scale, color: "text-[var(--medium)]" },
  lessons_learned: { icon: Lightbulb, color: "text-[var(--high)]" },
};

function buildContent(category: string, values: Record<string, string | string[]>): string {
  const schema = CATEGORY_SCHEMAS[category] || [];
  return schema
    .map((f) => {
      const v = values[f.key];
      const body = f.type === "steps"
        ? (Array.isArray(v) ? v : []).filter((s) => s.trim()).map((s, i) => `${i + 1}. ${s}`).join("\n")
        : (typeof v === "string" ? v : "");
      return `## ${f.label}\n${body}`;
    })
    .join("\n\n");
}

function parseContent(content: string): { header: string; body: string; steps: string[] | null }[] {
  const parts = content.split(/\n(?=## )/g).map((s) => s.trim()).filter(Boolean);
  if (parts.length === 0 || !parts[0].startsWith("## ")) {
    return [{ header: "", body: content, steps: null }];
  }
  return parts.map((part) => {
    const [firstLine, ...rest] = part.split("\n");
    const header = firstLine.replace(/^##\s*/, "");
    const body = rest.join("\n").trim();
    const lines = body.split("\n").map((l) => l.trim()).filter(Boolean);
    const isStepList = lines.length > 0 && lines.every((l) => /^\d+\.\s/.test(l));
    return { header, body, steps: isStepList ? lines.map((l) => l.replace(/^\d+\.\s/, "")) : null };
  });
}

function StepsInput({ values, onChange, placeholder }: { values: string[]; onChange: (v: string[]) => void; placeholder?: string }) {
  const list = values.length > 0 ? values : [""];
  return (
    <div className="space-y-2">
      {list.map((v, i) => (
        <div key={i} className="flex items-center gap-2">
          <span className="text-xs text-[var(--text-dim)] w-5 shrink-0">{i + 1}.</span>
          <Input
            value={v}
            placeholder={placeholder}
            onChange={(e) => {
              const next = [...list];
              next[i] = e.target.value;
              onChange(next);
            }}
            className="w-full"
          />
          {list.length > 1 && (
            <button type="button" onClick={() => onChange(list.filter((_, idx) => idx !== i))} className="text-[var(--text-dim)] hover:text-[var(--critical)] shrink-0">
              <X size={14} />
            </button>
          )}
        </div>
      ))}
      <button type="button" onClick={() => onChange([...list, ""])} className="text-xs text-[var(--brand)] hover:underline flex items-center gap-1">
        <Plus size={12} /> Add step
      </button>
    </div>
  );
}

export default function KnowledgePage() {
  const [docs, setDocs] = useState<KnowledgeDoc[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [selected, setSelected] = useState<{ id: number; title: string; content: string; category: string } | null>(null);
  const [title, setTitle] = useState("");
  const [category, setCategory] = useState("playbook");
  const [fieldValues, setFieldValues] = useState<Record<string, string | string[]>>({});
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    load();
  }, []);

  useEffect(() => {
    setFieldValues({});
  }, [category]);

  function load() {
    api.get<{ docs: KnowledgeDoc[] }>("/knowledge").then((r) => setDocs(r.docs));
  }

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const content = buildContent(category, fieldValues);
      await api.post("/knowledge", { title, category, content, tags: [] });
      setTitle("");
      setFieldValues({});
      setShowForm(false);
      load();
    } finally {
      setBusy(false);
    }
  }

  function openDoc(id: number) {
    api.get<{ id: number; title: string; content: string; category: string }>(`/knowledge/${id}`).then(setSelected);
  }

  async function removeDoc(id: number) {
    if (!confirm("Delete this document? The AI assistant will no longer be able to retrieve it.")) return;
    await api.del(`/knowledge/${id}`);
    setSelected(null);
    load();
  }

  const schema = CATEGORY_SCHEMAS[category] || [];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">Knowledge Base</h1>
          <p className="text-sm text-[var(--text-muted)] mt-1">Internal playbooks and guides — indexed for the AI assistant to retrieve</p>
        </div>
        <Button onClick={() => setShowForm((s) => !s)} className="flex items-center gap-2">
          <Plus size={14} /> New Document
        </Button>
      </div>

      {showForm && (
        <Card>
          <form onSubmit={create} className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs text-[var(--text-muted)] block mb-1">Title</label>
                <Input value={title} onChange={(e) => setTitle(e.target.value)} required className="w-full" />
              </div>
              <div>
                <label className="text-xs text-[var(--text-muted)] block mb-1">Document Type</label>
                <Select value={category} onChange={(e) => setCategory(e.target.value)} className="w-full">
                  {CATEGORIES.map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
                </Select>
              </div>
            </div>

            {schema.map((f) => (
              <div key={f.key}>
                <label className="text-xs text-[var(--text-muted)] block mb-1">{f.label}</label>
                {f.type === "steps" ? (
                  <StepsInput
                    values={(fieldValues[f.key] as string[]) || []}
                    onChange={(v) => setFieldValues((prev) => ({ ...prev, [f.key]: v }))}
                    placeholder={f.placeholder}
                  />
                ) : (
                  <textarea
                    value={(fieldValues[f.key] as string) || ""}
                    onChange={(e) => setFieldValues((prev) => ({ ...prev, [f.key]: e.target.value }))}
                    placeholder={f.placeholder}
                    required
                    rows={3}
                    className="w-full bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm outline-none focus:border-[var(--brand)]"
                  />
                )}
              </div>
            ))}

            <Button type="submit" disabled={busy}>{busy ? "Saving..." : "Save Document"}</Button>
          </form>
        </Card>
      )}

      {docs.length === 0 ? (
        <Card><EmptyState title="No knowledge base documents yet" hint="Add playbooks and remediation guides so the AI assistant can retrieve them." /></Card>
      ) : (
        <div className="grid grid-cols-2 gap-4">
          {docs.map((d) => {
            const meta = CATEGORY_META[d.category] || { icon: BookOpen, color: "text-[var(--brand)]" };
            const Icon = meta.icon;
            return (
              <button key={d.id} onClick={() => openDoc(d.id)} className="text-left bg-[var(--surface)] border border-[var(--border)] rounded-xl p-4 hover:border-[var(--brand)] transition-colors">
                <div className="flex items-center gap-2 mb-2">
                  <Icon size={14} className={meta.color} />
                  <span className="text-[10px] uppercase tracking-wide text-[var(--text-muted)]">{d.category.replace("_", " ")}</span>
                </div>
                <div className="text-sm font-medium">{d.title}</div>
                <div className="text-xs text-[var(--text-dim)] mt-2">{d.created_by} · {new Date(d.updated_at).toLocaleDateString()}</div>
              </button>
            );
          })}
        </div>
      )}

      {selected && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-8" onClick={() => setSelected(null)}>
          <div className="bg-[var(--surface)] border border-[var(--border)] rounded-xl max-w-2xl w-full max-h-[80vh] overflow-y-auto p-6" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-start justify-between mb-1">
              <div className="flex items-center gap-2">
                {(() => {
                  const meta = CATEGORY_META[selected.category] || { icon: BookOpen, color: "text-[var(--brand)]" };
                  const Icon = meta.icon;
                  return <Icon size={16} className={meta.color} />;
                })()}
                <span className="text-[10px] uppercase tracking-wide text-[var(--text-muted)]">{selected.category.replace("_", " ")}</span>
              </div>
              <div className="flex items-center gap-3">
                <button onClick={() => removeDoc(selected.id)} className="text-[var(--text-muted)] hover:text-[var(--critical)]" title="Delete document">
                  <Trash2 size={16} />
                </button>
                <button onClick={() => setSelected(null)} className="text-[var(--text-muted)] hover:text-[var(--text)]">✕</button>
              </div>
            </div>
            <h2 className="text-lg font-bold mb-4">{selected.title}</h2>

            <div className="space-y-5">
              {parseContent(selected.content).map((section, i) => (
                <div key={i}>
                  {section.header && (
                    <div className="text-xs font-semibold uppercase tracking-wide text-[var(--brand)] mb-2">{section.header}</div>
                  )}
                  {section.steps ? (
                    <ol className="relative border-l border-[var(--border)] ml-2 space-y-3">
                      {section.steps.map((step, si) => (
                        <li key={si} className="pl-4 relative">
                          <span className="absolute -left-[7px] top-0.5 w-3 h-3 rounded-full bg-[var(--brand)] border-2 border-[var(--surface)]" />
                          <span className="text-sm text-[var(--text)]">{step}</span>
                        </li>
                      ))}
                    </ol>
                  ) : (
                    <div className="text-sm whitespace-pre-wrap text-[var(--text-muted)]">{section.body}</div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
