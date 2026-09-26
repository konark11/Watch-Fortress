"""
RAG Query Engine - the brains behind the "Ask questions like..." examples
in the spec:

  "Why is this vulnerability dangerous?"          -> knowledge retrieval
  "How do I fix CVE-2024-3400?"                    -> knowledge retrieval
  "Show all critical SQL Injection findings"       -> structured DB query
  "Which hosts have privilege escalation risks?"   -> structured DB query

Rather than forcing every question through unstructured text retrieval
(which is a poor fit for "show me X" data questions - retrieval can find
relevant CONTEXT about SQL injection, but it can't enumerate rows from
your actual scan data), the engine first checks whether the question looks
like a request for live platform data and, if so, answers it with a real
SQL query against the Vulnerability/Asset tables. Otherwise it falls back
to TF-IDF retrieval + the configured generation backend (rag/llm_providers).
"""
from __future__ import annotations
import re
from sqlalchemy.orm import Session
from sqlalchemy import or_

from models.database import Vulnerability, Asset, Severity
from rag.retriever import TfidfRetriever
from rag.corpus import build_corpus
from rag.llm_providers import get_provider

_retriever = TfidfRetriever()
_indexed = False

VULN_TYPE_KEYWORDS = {
    "sql injection": ["sql injection", "sqli"],
    "cross-site scripting": ["xss", "cross-site scripting", "cross site scripting"],
    "privilege escalation": ["privilege escalation", "priv esc"],
    "remote code execution": ["remote code execution", "rce", "command injection"],
    "credential": ["credential", "password", "authentication"],
    "denial of service": ["denial of service", "dos "],
    "exposed panel": ["exposed panel", "exposure"],
}

SEVERITIES = {s.value for s in Severity}

# Small-talk / help intents. These aren't knowledge questions at all, so
# routing them through TF-IDF retrieval will (correctly) find nothing and
# produce a confusing "couldn't find anything" reply. Handle them directly
# instead, with a short greeting plus a few example questions the assistant
# can actually answer.
_GREETING_RE = re.compile(
    r"^\s*(hi|hello|hey|hiya|yo|howdy|sup|good\s?(morning|afternoon|evening))\s*[!.?]*\s*$",
    re.IGNORECASE,
)
_HELP_RE = re.compile(
    r"^\s*(help|what can you do|what do you do|how does this work|"
    r"who are you|what are you)\s*[!.?]*\s*$",
    re.IGNORECASE,
)

_EXAMPLE_QUESTIONS = [
    "Why is this vulnerability dangerous? (mention a CVE or finding title)",
    "How do I fix CVE-2024-3400?",
    "Show all critical SQL Injection findings",
    "Which hosts have privilege escalation risks?",
]


def _greeting_or_help_answer(db: Session, is_help: bool) -> dict:
    ensure_indexed(db)
    doc_count = len(_retriever.docs)
    examples = "\n".join(f"- {q}" for q in _EXAMPLE_QUESTIONS)
    if is_help:
        intro = (
            f"I'm the platform's security assistant. I answer questions two ways: by "
            f"retrieving from a local knowledge base of {doc_count} CVE/CWE/CAPEC/ATT&CK/OWASP "
            f"entries and any internal docs you've added, or by querying your live scan data "
            f"directly for questions like \"show\" or \"list\"."
        )
    else:
        intro = "Hi! I'm your security assistant."
    return {
        "answer": f"{intro}\n\nHere's what I can help with:\n{examples}",
        "sources": [],
        "structured_results": [],
    }


def ensure_indexed(db: Session, force: bool = False):
    global _indexed
    if _indexed and not force:
        return
    _retriever.index(build_corpus(db))
    _indexed = True


def _looks_like_data_question(question: str) -> bool:
    q = question.lower()
    triggers = ["show", "list", "which host", "which asset", "how many", "find all", "display"]
    return any(t in q for t in triggers)


def _answer_data_question(db: Session, question: str) -> dict:
    q = question.lower()

    severity_filter = next((s for s in SEVERITIES if s in q), None)
    type_filter = None
    for canonical, aliases in VULN_TYPE_KEYWORDS.items():
        if any(a in q for a in aliases):
            type_filter = canonical
            break

    wants_hosts = "host" in q or "asset" in q

    query = db.query(Vulnerability)
    if severity_filter:
        query = query.filter(Vulnerability.severity == severity_filter)
    if type_filter:
        like_terms = VULN_TYPE_KEYWORDS[type_filter]
        query = query.filter(or_(*[Vulnerability.canonical_title.ilike(f"%{t}%") for t in like_terms]))
    if "privilege escalation" in q and not type_filter:
        query = query.filter(Vulnerability.canonical_title.ilike("%privilege%"))

    results = query.order_by(Vulnerability.risk_score.desc()).limit(50).all()

    if not results:
        filters_desc = ", ".join(filter(None, [severity_filter, type_filter])) or "the specified criteria"
        return {
            "answer": f"No vulnerabilities currently in the database match {filters_desc}. "
                      f"Run or import a scan first, or try broader search terms.",
            "sources": [],
            "structured_results": [],
        }

    if wants_hosts:
        by_host: dict[str, list] = {}
        for v in results:
            asset = db.get(Asset, v.asset_id)
            key = asset.ip_address if asset else "unknown"
            by_host.setdefault(key, []).append(v.canonical_title)
        lines = [f"**{len(by_host)} host(s)** match your query:"]
        for host, titles in by_host.items():
            lines.append(f"- **{host}**: {len(titles)} finding(s) - {'; '.join(titles[:3])}{' ...' if len(titles) > 3 else ''}")
        answer = "\n".join(lines)
    else:
        lines = [f"Found **{len(results)}** matching vulnerability record(s):"]
        for v in results[:20]:
            asset = db.get(Asset, v.asset_id)
            host = asset.ip_address if asset else "unknown"
            lines.append(f"- [{v.severity.value.upper()}] {v.canonical_title} on {host} (risk score: {v.risk_score}, CVEs: {', '.join(v.cve_ids) or 'none'})")
        if len(results) > 20:
            lines.append(f"... and {len(results) - 20} more.")
        answer = "\n".join(lines)

    return {
        "answer": answer,
        "sources": [],
        "structured_results": [
            {
                "id": v.id, "title": v.canonical_title, "severity": v.severity.value,
                "risk_score": v.risk_score, "cve_ids": v.cve_ids,
                "asset_ip": (db.get(Asset, v.asset_id).ip_address if db.get(Asset, v.asset_id) else None),
            }
            for v in results
        ],
    }


def ask(db: Session, question: str, k: int = 5) -> dict:
    ensure_indexed(db)

    if _GREETING_RE.match(question):
        return _greeting_or_help_answer(db, is_help=False)
    if _HELP_RE.match(question):
        return _greeting_or_help_answer(db, is_help=True)

    if _looks_like_data_question(question):
        return _answer_data_question(db, question)

    # Also check: does the question reference a specific CVE ID we should
    # prioritize over generic similarity ranking?
    cve_match = re.search(r"CVE-\d{4}-\d{4,7}", question, re.IGNORECASE)
    retrieved = _retriever.retrieve(question, k=k)
    if cve_match:
        cve_id = cve_match.group(0).upper()
        exact = [d for d in _retriever.docs if d["id"] == f"cve:{cve_id}"]
        if exact and not any(d["id"] == f"cve:{cve_id}" for d, _ in retrieved):
            retrieved = [(exact[0], 1.0)] + retrieved[: k - 1]

    provider = get_provider()
    answer_text = provider.generate(question, retrieved)

    return {
        "answer": answer_text,
        "sources": [{"source": d["source"], "title": d["title"], "relevance": round(score, 3)} for d, score in retrieved],
        "structured_results": [],
        "provider": provider.name,
    }
