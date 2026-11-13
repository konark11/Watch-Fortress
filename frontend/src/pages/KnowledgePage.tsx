import { useEffect, useState } from "react";
import {
  Plus,
  BookOpen,
  ListChecks,
  Bug,
  Wrench,
  Scale,
  Lightbulb,
  X,
  Trash2,
  Upload,
} from "lucide-react";
import { api } from "../api/client";
import type { KnowledgeDoc } from "../types";
import {
  Card,
  Button,
  Input,
  Select,
  EmptyState,
  Drawer,
  SearchInput,
} from "../components/ui";

type FieldType = "textarea" | "steps";
type FieldSchema = { key: string; label: string; type: FieldType; placeholder?: string };

const CATEGORIES = [
  { value: "playbook", label: "Playbook" },
  { value: "vulnerability_writeup", label: "Vulnerability Write-up" },
  { value: "remediation_guide", label: "Remediation Guide" },
  { value: "organization_policy", label: "Organization Policy" },
  { value: "lessons_learned", label: "Lessons Learned" },
];

const CATEGORY_SCHEMAS: Record<string, FieldSchema[]> = {
  playbook: [
    { key: "Objective", label: "Objective", type: "textarea", placeholder: "What this playbook accomplishes and when to use it" },
    { key: "Steps", label: "Execution Steps", type: "steps", placeholder: "e.g. Isolate the affected host from the internal VLAN" },
  ],
  vulnerability_writeup: [
    { key: "Summary", label: "Executive Summary", type: "textarea", placeholder: "What the vulnerability is, in a sentence or two" },
    { key: "Affected Systems", label: "Affected Systems & Scope", type: "textarea", placeholder: "Which assets, services, or software versions are exposed" },
    { key: "Impact", label: "Threat Impact Analysis", type: "textarea", placeholder: "What an adversary could actually execute or exfiltrate" },
    { key: "Evidence", label: "Evidence & Technical Details", type: "textarea", placeholder: "Proof-of-concept notes, scan output, or raw request samples" },
  ],
  remediation_guide: [
    { key: "Remediation Steps", label: "Remediation & Patch Steps", type: "steps", placeholder: "e.g. Apply vendor hotfix or configure firewall blocklist" },
    { key: "Verification", label: "Verification Procedure", type: "textarea", placeholder: "How to confirm the mitigation successfully eliminated exposure" },
  ],
  organization_policy: [
    { key: "Policy Statement", label: "Policy Requirement Statement", type: "textarea", placeholder: "The exact governance rule or baseline requirement" },
    { key: "Scope", label: "Applicability Scope", type: "textarea", placeholder: "Who and what infrastructure this policy governs" },
    { key: "Enforcement", label: "Audit & Enforcement", type: "textarea", placeholder: "Verification cadence and escalation path" },
  ],
  lessons_learned: [
    { key: "What Happened", label: "Incident Chronology", type: "textarea", placeholder: "Factual account of the security event or exercise" },
    { key: "Root Cause", label: "Root Cause Analysis", type: "textarea", placeholder: "The underlying configuration or architecture vulnerability" },
    { key: "Action Items", label: "Corrective Action Items", type: "steps", placeholder: "e.g. Add automated regression scan to CI/CD pipeline" },
  ],
};

const CATEGORY_META: Record<string, { icon: typeof BookOpen; color: string; badge: string }> = {
  playbook: { icon: ListChecks, color: "text-[var(--text)]", badge: "bg-[var(--surface-2)] text-[var(--text-secondary)] border-[var(--border)]" },
  vulnerability_writeup: { icon: Bug, color: "text-[var(--critical)]", badge: "bg-[var(--surface-2)] text-[var(--critical)] border-[var(--border)]" },
  remediation_guide: { icon: Wrench, color: "text-[var(--low)]", badge: "bg-[var(--surface-2)] text-[var(--low)] border-[var(--border)]" },
  organization_policy: { icon: Scale, color: "text-[var(--medium)]", badge: "bg-[var(--surface-2)] text-[var(--medium)] border-[var(--border)]" },
  lessons_learned: { icon: Lightbulb, color: "text-[var(--high)]", badge: "bg-[var(--surface-2)] text-[var(--high)] border-[var(--border)]" },
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
  const cleaned = (content || "").replace(/^#[^#\n].*\n*/, "").trim();
  const parts = cleaned.split(/\n(?=## )/g).map((s) => s.trim()).filter(Boolean);
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

function StepsInput({
  values,
  onChange,
  placeholder,
}: {
  values: string[];
  onChange: (v: string[]) => void;
  placeholder?: string;
}) {
  const list = values.length > 0 ? values : [""];
  return (
    <div className="space-y-2">
      {list.map((v, i) => (
        <div key={i} className="flex items-center gap-2">
          <span className="text-xs font-mono-data text-[var(--text-dim)] w-5 shrink-0">
            {i + 1}.
          </span>
          <Input
            value={v}
            placeholder={placeholder}
            onChange={(e) => {
              const next = [...list];
              next[i] = e.target.value;
              onChange(next);
            }}
            className="w-full text-xs font-mono-data"
          />
          {list.length > 1 && (
            <button
              type="button"
              onClick={() => onChange(list.filter((_, idx) => idx !== i))}
              className="p-1 text-[var(--text-dim)] hover:text-[var(--critical)] rounded transition-colors cursor-pointer shrink-0"
            >
              <X size={15} />
            </button>
          )}
        </div>
      ))}
      <button
        type="button"
        onClick={() => onChange([...list, ""])}
        className="text-xs font-mono-data text-[var(--brand)] hover:underline flex items-center gap-1.5 pt-1 cursor-pointer"
      >
        <Plus size={13} /> Add next step
      </button>
    </div>
  );
}

export default function KnowledgePage() {
  const [docs, setDocs] = useState<KnowledgeDoc[]>([]);
  const [search, setSearch] = useState("");
  const [selectedCategory, setSelectedCategory] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [formMode, setFormMode] = useState<"manual" | "upload">("manual");
  const [file, setFile] = useState<File | null>(null);
  const [tags, setTags] = useState("");
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
      if (formMode === "upload") {
        if (!file) return;
        const form = new FormData();
        form.append("file", file);
        if (title.trim()) form.append("title", title.trim());
        form.append("category", category);
        form.append("tags", tags);
        await api.postForm("/knowledge/upload", form);
      } else {
        const content = buildContent(category, fieldValues);
        await api.post("/knowledge", { title, category, content, tags: [] });
      }
      setTitle("");
      setFieldValues({});
      setFile(null);
      setTags("");
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
    if (!confirm("Delete this knowledge document? The AI assistant will no longer be able to retrieve it.")) return;
    await api.del(`/knowledge/${id}`);
    setSelected(null);
    load();
  }

  const filteredDocs = docs.filter((d) => {
    const matchesCat = !selectedCategory || d.category === selectedCategory;
    const matchesSearch =
      !search.trim() ||
      d.title.toLowerCase().includes(search.toLowerCase()) ||
      d.category.toLowerCase().includes(search.toLowerCase());
    return matchesCat && matchesSearch;
  });

  const schema = CATEGORY_SCHEMAS[category] || [];

  return (
    <div className="space-y-6">
      {/* Title & Filter Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[var(--text)]">
            Intelligence Knowledge Base
          </h1>
          <p className="text-xs text-[var(--text-muted)] mt-1">
            Standard operating procedures, playbooks, and mitigation guides indexed for the RAG assistant
          </p>
        </div>
        <Button
          onClick={() => setShowForm((s) => !s)}
          variant={showForm ? "secondary" : "primary"}
          size="sm"
          icon={Plus}
        >
          {showForm ? "Cancel" : "Add Knowledge Doc"}
        </Button>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-1 bg-[var(--surface)] border border-[var(--border)] rounded-[5px] p-1 overflow-x-auto">
          <button
            onClick={() => setSelectedCategory("")}
            className={`px-2.5 py-1 rounded-[4px] text-xs transition-colors cursor-pointer ${
              selectedCategory === ""
                ? "bg-[var(--surface-2)] text-[var(--text)] font-medium border border-[var(--border-strong)]"
                : "text-[var(--text-secondary)] hover:text-[var(--text)] hover:bg-[var(--surface-hover)] border border-transparent"
            }`}
          >
            All docs ({docs.length})
          </button>
          {CATEGORIES.map((cat) => (
            <button
              key={cat.value}
              onClick={() => setSelectedCategory(cat.value)}
              className={`px-2.5 py-1 rounded-[4px] text-xs transition-colors cursor-pointer ${
                selectedCategory === cat.value
                  ? "bg-[var(--surface-2)] text-[var(--text)] font-medium border border-[var(--border-strong)]"
                  : "text-[var(--text-secondary)] hover:text-[var(--text)] hover:bg-[var(--surface-hover)] border border-transparent"
              }`}
            >
              {cat.label}
            </button>
          ))}
        </div>

        <div className="flex-1 min-w-[200px]">
          <SearchInput
            placeholder="Search documents by title..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onClear={() => setSearch("")}
          />
        </div>
      </div>

      {/* Form for manual write or file upload */}
      {showForm && (
        <Card
          header="Add New Knowledge Base Document"
          subtitle="Documents are parsed, chunked, and embedded into local TF-IDF vector index"
        >
          <form onSubmit={create} className="space-y-4">
            <div className="flex gap-2 border-b border-[var(--border)] pb-3">
              <Button
                type="button"
                variant={formMode === "manual" ? "primary" : "secondary"}
                size="sm"
                icon={Plus}
                onClick={() => setFormMode("manual")}
              >
                Structured Authoring
              </Button>
              <Button
                type="button"
                variant={formMode === "upload" ? "primary" : "secondary"}
                size="sm"
                icon={Upload}
                onClick={() => setFormMode("upload")}
              >
                Upload File (DOCX, PDF, MD)
              </Button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-xs font-semibold text-[var(--text)] block mb-1.5">
                  Document Title
                </label>
                <Input
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  required={formMode === "manual"}
                  placeholder={formMode === "upload" ? "Optional (defaults to filename)" : "e.g. Critical RCE Response Playbook"}
                  className="w-full text-xs"
                />
              </div>
              <div>
                <label className="text-xs font-semibold text-[var(--text)] block mb-1.5">
                  Knowledge Classification
                </label>
                <Select
                  value={category}
                  onChange={(e) => setCategory(e.target.value)}
                  className="w-full text-xs font-mono-data"
                >
                  {CATEGORIES.map((c) => (
                    <option key={c.value} value={c.value}>
                      {c.label}
                    </option>
                  ))}
                </Select>
              </div>
            </div>

            {formMode === "upload" ? (
              <div className="space-y-3">
                <div className="border border-dashed border-[var(--border)] rounded-[5px] p-3 transition-colors bg-[var(--surface-2)]">
                  <Input
                    type="file"
                    accept=".docx,.pdf,.md,.markdown,.txt"
                    required
                    onChange={(e) => setFile(e.target.files?.[0] || null)}
                    className="w-full text-xs text-[var(--text-muted)] file:mr-3 file:py-1.5 file:px-3 file:rounded-lg file:border-0 file:bg-[var(--surface-3)] file:text-[var(--text)] file:text-xs cursor-pointer"
                  />
                  <p className="text-[11px] text-[var(--text-dim)] mt-2">
                    Accepts DOCX, PDF, Markdown, or Plain Text up to 10 MB. Ingests full text into the offline assistant index.
                  </p>
                </div>
                <div>
                  <label className="text-xs font-semibold text-[var(--text)] block mb-1.5">
                    Metadata Tags (comma-separated)
                  </label>
                  <Input
                    value={tags}
                    onChange={(e) => setTags(e.target.value)}
                    placeholder="incident-response, linux, rce, privilege-escalation"
                    className="w-full text-xs font-mono-data"
                  />
                </div>
              </div>
            ) : (
              schema.map((f) => (
                <div key={f.key}>
                  <label className="text-xs font-semibold text-[var(--text)] block mb-1.5">
                    {f.label}
                  </label>
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
                      className="w-full bg-[var(--surface-2)] border border-[var(--border)] rounded-[5px] px-3 py-2 text-xs text-[var(--text)] focus:border-[var(--accent)] focus:outline-none transition-colors"
                    />
                  )}
                </div>
              ))
            )}

            <div className="flex justify-end pt-2">
              <Button type="submit" disabled={busy} variant="primary" size="sm">
                {busy
                  ? formMode === "upload"
                    ? "Chunking & Indexing..."
                    : "Saving..."
                  : formMode === "upload"
                  ? "Upload & Index Knowledge"
                  : "Save Knowledge Document"}
              </Button>
            </div>
          </form>
        </Card>
      )}

      {/* Document Grid */}
      {filteredDocs.length === 0 ? (
        <Card>
          <EmptyState
            title="No knowledge base documents match your filter"
            hint="Add remediation playbooks and security policies so your team and the AI assistant can reference them."
          />
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filteredDocs.map((d) => {
            const meta = CATEGORY_META[d.category] || {
              icon: BookOpen,
              color: "text-[var(--text)]",
              badge: "bg-[var(--surface-2)] text-[var(--text-secondary)] border-[var(--border)]",
            };
            const Icon = meta.icon;
            return (
              <button
                key={d.id}
                onClick={() => openDoc(d.id)}
                className="text-left bg-[var(--surface)] border border-[var(--border)] hover:border-[var(--border-strong)] rounded-[5px] p-3.5 transition-colors flex flex-col justify-between cursor-pointer"
              >
                <div>
                  <div className="flex items-center justify-between mb-2.5">
                    <span
                      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[10px] font-mono-data font-bold uppercase border ${meta.badge}`}
                    >
                      <Icon size={12} className={meta.color} />
                      {d.category.replace("_", " ")}
                    </span>
                    <span className="text-[11px] font-mono-data text-[var(--text-dim)]">
                      {new Date(d.updated_at).toLocaleDateString()}
                    </span>
                  </div>

                  <h3 className="font-semibold text-sm text-[var(--text)] group-hover:text-[var(--brand)] transition-colors leading-snug">
                    {d.title}
                  </h3>
                </div>

                <div className="pt-3 mt-3 border-t border-[var(--border-soft)] flex items-center justify-between text-xs font-mono-data text-[var(--text-dim)]">
                  <span>Author: {d.source_filename || d.created_by || "System"}</span>
                  <span>
                    Indexed: <strong className="text-[var(--text)]">{d.indexed_chunk_count || 0}</strong>/{d.chunk_count || 0} chunks
                  </span>
                </div>
              </button>
            );
          })}
        </div>
      )}

      {/* Document Reader Drawer */}
      <Drawer
        isOpen={Boolean(selected)}
        onClose={() => setSelected(null)}
        width="640px"
        title={
          <div className="flex items-center justify-between gap-4">
            <div className="min-w-0">
              {selected && (
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-[10.5px] font-mono-data uppercase font-bold text-[var(--brand)]">
                    [{selected.category.replace("_", " ")}]
                  </span>
                </div>
              )}
              <h2 className="text-base font-bold text-[var(--text)] leading-snug">
                {selected?.title}
              </h2>
            </div>
            {selected && (
              <button
                onClick={() => removeDoc(selected.id)}
                className="p-1.5 text-[var(--text-dim)] hover:text-[var(--critical)] rounded-lg hover:bg-[var(--surface-2)] transition-colors cursor-pointer"
                title="Delete document"
              >
                <Trash2 size={16} />
              </button>
            )}
          </div>
        }
      >
        {selected && (
          <div className="space-y-6">
            {parseContent(selected.content).map((section, i) => (
              <div key={i} className="bg-[var(--surface-2)] border border-[var(--border)] rounded-[5px] p-3 text-xs">
                {section.header && (
                  <h4 className="text-xs font-mono-data uppercase font-bold text-[var(--brand)] tracking-wider mb-2.5">
                    {section.header}
                  </h4>
                )}
                {section.steps ? (
                  <ol className="space-y-2.5 pl-1">
                    {section.steps.map((step, si) => (
                      <li key={si} className="flex items-start gap-2.5 text-xs font-mono-data text-[var(--text)] leading-relaxed">
                        <span className="w-5 h-5 rounded-md bg-[var(--surface-3)] border border-[var(--border)] flex items-center justify-center font-bold text-[10px] text-[var(--brand)] shrink-0 mt-0.5">
                          {si + 1}
                        </span>
                        <span>{step}</span>
                      </li>
                    ))}
                  </ol>
                ) : (
                  <div className="text-xs text-[var(--text)] leading-relaxed whitespace-pre-wrap font-sans">
                    {section.body}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </Drawer>
    </div>
  );
}
