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
to dense-vector retrieval + the configured generation backend (rag/llm_providers).
"""
from __future__ import annotations
import logging
import re
from sqlalchemy.orm import Session
from sqlalchemy import or_, text

from models.database import Vulnerability, Finding, Asset, Port, Scan, ScanStatus, Severity
from knowledge.mapper import kb
from rag.retriever import HybridRetriever
from rag.relevance import normalize_security_query
from rag.embeddings import active_embedding_metadata, embed_texts
from rag.llm_providers import get_provider, provider_status, validate_provider_configuration
from rag.internet_lookup import lookup_question
from rag.reranker import rerank
from rag.settings import DENSE_TOP_K, FINAL_EVIDENCE_K, FUSION_K, RERANK_ENABLED, RERANK_K
from rag.indexing.repository import latest_run
from rag.retrieval.service import backend_name, capability as retrieval_capability
from security.login_analysis import analyze_login_failures, render_login_analysis
from observability import answer_outcomes, citations, increment, observe, rag_latency, rag_stage_duration, retrieval_candidates, span
import time

_retriever = HybridRetriever()
_indexed = False
_index_error: str | None = None
logger = logging.getLogger(__name__)


class EmbeddingCompatibilityError(RuntimeError):
    """Raised when persisted vectors cannot safely be used by the active index."""

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
# routing them through vector retrieval will (correctly) find nothing and
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

_KNOWN_VULNERABILITY_ALIASES = {
    "terrapin": {"terrapin", "cve-2023-48795"},
    "openssh terrapin": {"openssh terrapin", "terrapin", "cve-2023-48795"},
    "terrapin attack": {"terrapin attack", "terrapin", "cve-2023-48795"},
    "log4shell": {"log4shell", "cve-2021-44228"},
    "heartbleed": {"heartbleed", "cve-2014-0160"},
    "shellshock": {"shellshock", "cve-2014-6271"},
    "proxylogon": {"proxylogon", "cve-2021-26855"},
    "printnightmare": {"printnightmare", "cve-2021-34527"},
    "dirty pipe": {"dirty pipe", "cve-2022-0847"},
    "eternalblue": {"eternalblue", "cve-2017-0144"},
    "bluekeep": {"bluekeep", "cve-2019-0708"},
}

_ANAPHORA_OR_ATTR_PATTERN = re.compile(
    r"\b(?:this|it|that|the vulnerability|the vuln|the cve|the bug|the issue|"
    r"explain|tell me|describe|"
    r"cvss|score|severity|fix|patch|remediat|mitigat|exploit|exploitable|kev|cisa|affected|version|impact|cwe)\b",
    re.IGNORECASE,
)


def resolve_focal_context(
    question: str,
    history: list[dict] | None = None,
) -> tuple[str, str | None]:
    """Resolve explicit or inherited focal vulnerability target from the dialogue."""
    normalized_q = normalize_security_query(question)
    cve_direct = re.search(r"\bCVE-\d{4}-\d{4,7}\b", normalized_q, re.IGNORECASE)
    if cve_direct:
        return normalized_q, cve_direct.group(0).upper()

    lowered = normalized_q.lower()
    for alias, cve_set in _KNOWN_VULNERABILITY_ALIASES.items():
        if alias in lowered:
            for item in cve_set:
                if item.startswith("cve-"):
                    return normalized_q, item.upper()

    if _ANAPHORA_OR_ATTR_PATTERN.search(normalized_q) and history:
        for turn in reversed(history[-12:]):
            content = normalize_security_query(turn.get("content", ""))
            match = re.search(r"\bCVE-\d{4}-\d{4,7}\b", content, re.IGNORECASE)
            if match:
                active_cve = match.group(0).upper()
                return f"{normalized_q} (referring to {active_cve})", active_cve
            content_lower = content.lower()
            for alias, cve_set in _KNOWN_VULNERABILITY_ALIASES.items():
                if alias in content_lower:
                    for item in cve_set:
                        if item.startswith("cve-"):
                            active_cve = item.upper()
                            return f"{normalized_q} (referring to {active_cve})", active_cve

    return normalized_q, None


def _greeting_or_help_answer(db: Session, is_help: bool) -> dict:
    ensure_indexed(db)
    examples = "\n".join(f"- {q}" for q in _EXAMPLE_QUESTIONS)
    if is_help:
        intro = (
            "I'm your security assistant. I can explain security issues, help with fixes, "
            "and look up findings from your scans."
        )
    else:
        intro = "Hi! I'm your security assistant."
    return {
        "answer": f"{intro}\n\nHere's what I can help with:\n{examples}",
        "sources": [],
        "structured_results": [],
    }


def ensure_indexed(db: Session, force: bool = False):
    global _indexed, _index_error
    run = latest_run(db)
    if not run or run["state"] not in {"ready", "stale"}:
        _indexed = False
        _index_error = "RAG index is not ready; run the explicit bootstrap indexing job."
        return
    active = active_embedding_metadata()
    if run["embedding_dimension"] != active["dimension"] or run["embedding_model"] != active["model"]:
        raise EmbeddingCompatibilityError(
            "Persisted retrieval vectors are incompatible with the active embedding model; "
            "run a deliberate full reindex."
        )
    _indexed = True
    _index_error = None


def index_status(db: Session) -> dict:
    """Return safe operational state without exposing environment secrets."""
    active = active_embedding_metadata()
    run = latest_run(db)
    counts = db.execute(text(
        "SELECT COUNT(*) FROM rag_index_records WHERE deleted_at IS NULL"
    )).scalar_one()
    state = "not_indexed" if not run else run["state"]
    db_capability = retrieval_capability(db)
    if backend_name(db) == "postgres" and not db_capability.get("available"):
        state = "unavailable"
    if run and (
        run["embedding_dimension"] != active["dimension"]
        or run["embedding_model"] != active["model"]
    ):
        state = "incompatible"
    return {
        "state": state,
        "document_count": int(counts),
        "stored_embedding_count": int(counts),
        "active_embedding": active,
        "last_job": dict(run) if run else None,
        "last_index_summary": {
            key: run[key] for key in (
                "records_scanned", "added", "updated", "unchanged", "deleted", "failed"
            )
        } if run else None,
        "remediation": (
            "Run `python -m rag.bootstrap` for the initial incremental index; "
            "enable RAG_FULL_REINDEX_ENABLED only for an administrator-approved rebuild."
            if state != "ready" else None
        ),
        "backend": backend_name(db),
        "capability": db_capability,
    }


def _rerank_candidates(
    question: str,
    retrieved: list[tuple[dict, float]],
    k: int,
) -> list[tuple[dict, float]]:
    """Optionally score a broad local candidate set with a query-document model."""
    if not RERANK_ENABLED or len(retrieved) <= 1:
        return retrieved[:k]
    candidates = retrieved[:min(len(retrieved), max(k, RERANK_K))]
    try:
        scores = rerank(question, [doc["text"] for doc, _ in candidates])
    except (ImportError, RuntimeError, ValueError, TypeError, OSError) as exc:
        logger.warning("Reranking unavailable; using hybrid retrieval order: %s", exc)
        return retrieved[:k]
    reranked = sorted(
        zip((doc for doc, _ in candidates), scores),
        key=lambda item: item[1],
        reverse=True,
    )
    selected: list[tuple[dict, float]] = []
    seen_documents: set[str] = set()
    for doc, score in reranked:
        document_key = doc.get("metadata", {}).get("document_id")
        if not document_key:
            document_key = re.sub(r"\s+\(chunk\s+\d+\)$", "", doc.get("title", doc["id"]))
        if document_key in seen_documents:
            continue
        seen_documents.add(document_key)
        selected.append((doc, score))
        if len(selected) == k:
            break
    return selected


def _looks_like_data_question(question: str) -> bool:
    q = question.lower()
    triggers = ["show", "list", "which host", "which asset", "how many", "find all", "display"]
    return any(t in q for t in triggers)


def _is_recent_scan_question(question: str) -> bool:
    q = question.lower()
    return (
        "scan" in q
        and any(term in q for term in ("most recent", "latest", "last", "recent"))
    )


def _is_mitigation_follow_up(question: str) -> bool:
    q = question.lower()
    # If the user asks for explanation, difficulty assessment, or about a specific vulnerability/CVE,
    # let RAG/LLM handle it with rich context instead of returning a static scan findings list.
    if any(term in q for term in ("what is", "why", "how difficult", "explain", "tell me", "brother", "details", "strategy")):
        return False
    if any(alias in q for alias in _KNOWN_VULNERABILITY_ALIASES):
        return False
    if re.search(r"\bcve-\d{4}-\d{4,7}\b", q):
        return False
    # Only match generic scan mitigation questions
    return any(term in q for term in ("mitigate", "mitigation", "remediate", "remediation", "fix", "resolve"))


def _is_provenance_question(question: str) -> bool:
    q = question.lower()
    return any(term in q for term in ("where did", "source", "come from", "based on", "evidence"))


def _is_scan_list_question(question: str) -> bool:
    q = question.lower()
    return "scan" in q and any(term in q for term in ("all", "every", "more", "results", "vulnerab", "issues", "findings"))


def _is_explanation_follow_up(question: str) -> bool:
    q = question.lower().strip()
    return bool(re.search(r"\b(why|how come|what caused|what does that mean)\b", q))


def _is_scan_priority_follow_up(question: str) -> bool:
    q = question.lower().strip()
    if any(term in q for term in ("what is the cve", "which cve", "what cve", "cve id", "the cve")):
        return False
    priority_terms = (
        "important", "priority", "priorities", "prioritize", "care about",
        "care most", "fix first", "highest severity", "most critical",
        "top finding", "top priority", "worst finding", "worst issue",
        "which finding", "what finding", "main finding", "key finding",
        "first finding", "focus on", "most dangerous", "critical finding",
    )
    return any(term in q for term in priority_terms)


def _metadata_filter(question: str, active_cve: str | None = None):
    """Build pre-retrieval filters from explicit security metadata in a query."""
    lowered = normalize_security_query(question).lower()
    severity = next((value for value in SEVERITIES if value in lowered), None)
    port_match = re.search(r"\bport\s+(\d{1,5})\b", lowered)
    cve_match = re.search(r"\bcve-\d{4}-\d{4,7}\b", lowered, re.IGNORECASE)
    target_cve = cve_match.group(0).lower() if cve_match else (active_cve.lower() if active_cve else None)
    vm_match = re.search(
        r"\b(?:vm|host|asset|ip)\s+((?:\d{1,3}\.){3}\d{1,3})\b",
        lowered,
    )
    scan_doc_type = "Completed scan" if ("scan" in lowered and not any(term in lowered for term in ("port", "ports", "service", "open"))) else None
    document_type = next((
        source for term, source in {
            "cwe": "CWE", "capec": "CAPEC",
            "owasp": "OWASP", "mitre": "MITRE ATT&CK",
            "finding": "Scan finding",
        }.items() if term in lowered
    ), scan_doc_type)
    if not any((severity, port_match, target_cve, vm_match, document_type)):
        return None

    def matches(doc: dict) -> bool:
        metadata = doc.get("metadata", {})
        text = f"{doc.get('title', '')} {doc.get('text', '')}".lower()
        if document_type and not (
            metadata.get("document_type") == document_type
            or doc.get("source") == document_type
            or document_type.lower() in text
        ):
            return False
        if severity and metadata.get("severity") not in (None, severity, "unknown"):
            return False
        if port_match and port_match.group(1) not in text:
            return False
        if target_cve and target_cve not in text:
            return False
        if vm_match and vm_match.group(1) not in text:
            return False
        return True

    return matches


def _named_vulnerability_terms(question: str, active_cve: str | None = None) -> set[str]:
    """Return identifiers that must be present in evidence for specific asks."""
    lowered = normalize_security_query(question).lower()
    terms: set[str] = set(re.findall(r"\bcve-\d{4}-\d{4,7}\b", lowered))
    if active_cve:
        terms.add(active_cve.lower())
    for name, aliases in _KNOWN_VULNERABILITY_ALIASES.items():
        if name in lowered:
            terms.update(aliases)
    for keywords in VULN_TYPE_KEYWORDS.values():
        if any(keyword in lowered for keyword in keywords):
            terms.update(keywords)
    return terms


def _has_named_vulnerability_evidence(
    question: str,
    retrieved: list[tuple[dict, float]],
    active_cve: str | None = None,
) -> bool:
    terms = _named_vulnerability_terms(question, active_cve)
    if not terms:
        return True
    for document, _ in retrieved:
        haystack = f"{document.get('title', '')} {document.get('text', '')}".lower()
        if any(term in haystack for term in terms):
            return True
    return False


def _has_adequate_local_evidence(
    question: str,
    retrieved: list[tuple[dict, float]],
) -> bool:
    if not retrieved:
        return False
    stopwords = {
        "and", "are", "does", "how", "is", "it", "should", "the", "this",
        "to", "what", "why",
    }
    terms = {
        term for term in re.findall(r"[a-z0-9]+", question.lower())
        if len(term) >= 3 and term not in stopwords
    }
    if not terms:
        return False
    for document, _ in retrieved[:FINAL_EVIDENCE_K]:
        haystack = f"{document.get('title', '')} {document.get('text', '')}".lower()
        if sum(term in haystack for term in terms) >= min(2, len(terms)):
            return True
    return False


def _is_conceptual_question(question: str) -> bool:
    q = question.lower().strip()
    if re.search(r"\bcve-\d{4}-\d{4,7}\b", q):
        return False
    # Check for explanatory/conceptual inquiry patterns
    if re.search(r"\b(?:what is|what are|what does|why is|why do|how does|explain|tell me about|meaning of|definition of)\b", q):
        # If it specifically asks for host listing: "which hosts", "what hosts have", "how many hosts"
        if re.search(r"\b(?:which|what|how many)\s+(?:hosts?|systems?|assets?|machines?|ips?|servers?)\b", q):
            return False
        # If it specifically targets an IP or domain: "on 192.168.1.1", "in scanme.nmap.org"
        if re.search(r"\b(?:on|for|against|in)\s+(?:\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9.-]+\.[a-z]{2,})\b", q):
            return False
        # If it's asking how many are opened: "how many port 80 are opened"
        if "how many" in q and ("open" in q or "opened" in q):
            return False
        return True
    return False


def _is_general_question(question: str, active_cve: str | None = None) -> bool:
    """Identify stable conceptual questions that should not use weak CVE context."""
    if active_cve:
        return False
    lowered = normalize_security_query(question).lower().strip()
    if (
        re.search(r"\bcve-\d{4}-\d{4,7}\b", lowered)
        or any(alias in lowered for alias in _KNOWN_VULNERABILITY_ALIASES)
        or _looks_like_data_question(question)
        or re.search(r"\b(?:scan|finding|asset|host|ip address|cve)\b", lowered)
    ):
        return False
    if _is_conceptual_question(question):
        return True
    if re.search(r"\b(?:what is|what does|how does|define|explain)\b", lowered):
        return True
    return False


def _scope_retrieved_evidence(
    question: str,
    retrieved: list[tuple[dict, float]],
    active_cve: str | None = None,
) -> tuple[list[tuple[dict, float]], str | None]:
    """Keep generation context aligned with an explicit vulnerability target."""
    cve_target = active_cve
    if not cve_target:
        cve_match = re.search(r"\bcve-\d{4}-\d{4,7}\b", normalize_security_query(question), re.IGNORECASE)
        if cve_match:
            cve_target = cve_match.group(0).upper()
    if not cve_target:
        return retrieved, None
    target = cve_target.lower()
    scoped = [
        (document, score)
        for document, score in retrieved
        if target in f"{document.get('id', '')} {document.get('title', '')} {document.get('text', '')}".lower()
    ]
    if not scoped and retrieved:
        lowered_q = normalize_security_query(question).lower()
        matched_aliases = [alias for alias in _KNOWN_VULNERABILITY_ALIASES if alias in lowered_q]
        if matched_aliases:
            scoped = [
                (doc, score)
                for doc, score in retrieved
                if any(alias in f"{doc.get('title', '')} {doc.get('text', '')}".lower() for alias in matched_aliases)
            ]
    return (scoped or retrieved)[:FINAL_EVIDENCE_K], cve_target


def _answer_mentions_unrequested_cve(answer: str, target_cve: str | None) -> bool:
    if not target_cve:
        return False
    mentioned = {
        value.upper()
        for value in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", answer, re.IGNORECASE)
    }
    if not mentioned:
        return False
    # Only treat as unrequested if the target CVE was completely omitted
    # and only other CVEs were discussed
    return target_cve.upper() not in mentioned


def _should_use_nvd_fallback(
    retrieved: list[tuple[dict, float]],
    previous_user_questions: list[str],
    named_query: bool = False,
    local_evidence_adequate: bool = False,
    active_cve: str | None = None,
) -> bool:
    if not named_query or retrieved or local_evidence_adequate:
        return False
    # Always allow NVD lookup on the first question in a conversation.
    if not previous_user_questions:
        return True
    # Also allow NVD lookup on follow-up turns when the query targets a
    # specific CVE (explicit or resolved from an alias like "Terrapin").
    # This prevents "couldn't find grounded local evidence" when the user
    # asks a follow-up about a named vulnerability that isn't in local RAG.
    if active_cve:
        return True
    return False


def _metadata_criteria(question: str, active_cve: str | None = None) -> dict:
    lowered = normalize_security_query(question).lower()
    criteria: dict = {}
    severity = next((value for value in SEVERITIES if re.search(r"\b" + re.escape(value) + r"\b", lowered)), None)
    if severity:
        criteria["severity"] = severity
    port_match = re.search(r"\bport\s+(\d{1,5})\b", lowered)
    if port_match:
        criteria["port"] = int(port_match.group(1))
    cve_match = re.search(r"\bcve-\d{4}-\d{4,7}\b", lowered, re.IGNORECASE)
    if cve_match:
        criteria["cve"] = cve_match.group(0).upper()
    elif active_cve:
        criteria["cve"] = active_cve.upper()
    vm_match = re.search(
        r"\b(?:vm|host|asset|ip)\s+((?:\d{1,3}\.){3}\d{1,3})\b",
        lowered,
    )
    if vm_match:
        criteria["vm"] = vm_match.group(1)
    if re.search(r"\bscan\b", lowered) and not any(re.search(r"\b" + term + r"\b", lowered) for term in ("port", "ports", "service", "open")):
        criteria["document_type"] = "Completed scan"
    else:
        criteria["document_type"] = next((
            source for term, source in {
                "cwe": "CWE", "capec": "CAPEC",
                "owasp": "OWASP", "mitre": "MITRE ATT&CK",
                "finding": "Scan finding",
            }.items() if re.search(r"\b" + re.escape(term) + r"\b", lowered)
        ), None)
    return {key: value for key, value in criteria.items() if value is not None}


def production_retrieve(db: Session, question: str, k: int) -> list[tuple[dict, float]]:
    """Run the same persistent retrieval, filters, and local reranker as ``ask``.

    This deliberately does not call a generation provider, so evaluation and
    operational retrieval checks can exercise the production evidence path
    without making a paid/network request.
    """
    ensure_indexed(db)
    from rag.retrieval.service import retrieve as persistent_retrieve

    retrieved = persistent_retrieve(db, question, _metadata_criteria(question), k=FUSION_K)
    return _rerank_candidates(question, retrieved, min(k, FINAL_EVIDENCE_K))


def _latest_problematic_scan(db: Session) -> Scan | None:
    scan = (
        db.query(Scan)
        .filter(Scan.status == ScanStatus.COMPLETED, Scan.findings_count > 0)
        .order_by(Scan.finished_at.desc(), Scan.id.desc())
        .first()
    )
    if scan is None:
        scan = (
            db.query(Scan)
            .filter(Scan.status == ScanStatus.COMPLETED)
            .order_by(Scan.finished_at.desc(), Scan.id.desc())
            .first()
        )
    return scan


def _find_contextual_scan(db: Session, history: list[dict] | None = None) -> Scan | None:
    if history:
        for turn in reversed(history[-12:]):
            content = turn.get("content", "")
            targets = re.findall(r"\b[a-z0-9][a-z0-9.-]*\.[a-z]{2,}\b|\b\d{1,3}(?:\.\d{1,3}){3}\b", content.lower())
            for target in targets:
                scan = (
                    db.query(Scan)
                    .filter(Scan.status == ScanStatus.COMPLETED, Scan.findings_count > 0, Scan.target.ilike(f"%{target}%"))
                    .order_by(Scan.finished_at.desc(), Scan.id.desc())
                    .first()
                )
                if scan:
                    return scan
    return _latest_problematic_scan(db)


def _answer_recent_scan_priorities(db: Session, question: str, history: list[dict] | None = None) -> dict:
    scan = _find_contextual_scan(db, history)
    if scan is None:
        return _answer_recent_scan_question(db, problematic_only=True)
    findings = list(scan.findings)
    if not findings:
        return _answer_recent_scan_question(db, problematic_only=True)

    severity_weight = {
        Severity.CRITICAL: 5,
        Severity.HIGH: 4,
        Severity.MEDIUM: 3,
        Severity.LOW: 2,
        Severity.INFO: 1,
    }
    sorted_findings = sorted(
        findings,
        key=lambda f: (
            severity_weight.get(f.severity, 0),
            f.cvss_score or 0.0,
            1 if f.cve_ids else 0,
            f.id,
        ),
        reverse=True,
    )
    top_finding = sorted_findings[0]
    top_cves = ", ".join(top_finding.cve_ids or []) or "no CVE recorded"
    port_str = f":{top_finding.port_number}" if top_finding.port_number else ""
    loc_str = f"{top_finding.asset_ip or 'unknown host'}{port_str}"

    remediation = top_finding.solution
    if not remediation or not remediation.strip():
        remediation = "Apply the vendor patch or upgrade the vulnerable software/service, restrict unnecessary exposure, and rerun the scan to verify closure."
    else:
        remediation = " ".join(remediation.split())

    lines = [
        f"The most important finding to care about in the completed scan (**{scan.name}** on **{scan.target}**) is:",
        "",
        f"- **[{top_finding.severity.value.upper()}] {top_finding.title}** on `{loc_str}` ({top_cves})",
    ]
    if top_finding.description:
        desc = " ".join(top_finding.description.split())
        if len(desc) > 300:
            desc = desc[:297].rsplit(" ", 1)[0] + "..."
        lines.append(f"  - **Why it matters**: {desc}")
    else:
        lines.append(f"  - **Why it matters**: This is the highest-severity issue detected on `{loc_str}`.")

    lines.append(f"  - **Remediation**: {remediation}")

    secondary = sorted_findings[1:6]
    if secondary:
        lines.extend([
            "",
            "Next priorities to address after this:",
        ])
        for sf in secondary:
            sf_cves = f" ({', '.join(sf.cve_ids[:2])})" if sf.cve_ids else ""
            sf_port = f":{sf.port_number}" if sf.port_number else ""
            lines.append(f"- [{sf.severity.value.upper()}] {sf.title} on {sf.asset_ip or 'unknown host'}{sf_port}{sf_cves}")

    return {
        "answer": "\n".join(lines),
        "sources": [{
            "source": "Completed scan",
            "title": f"{scan.name} - {scan.target}",
            "relevance": 1.0,
        }],
        "structured_results": [{
            "scan_id": scan.id,
            "target": scan.target,
            "top_finding": {
                "id": top_finding.id,
                "title": top_finding.title,
                "severity": top_finding.severity.value,
                "cve_ids": top_finding.cve_ids or [],
                "asset_ip": top_finding.asset_ip,
                "port": top_finding.port_number,
                "solution": top_finding.solution,
            },
            "total_findings": len(findings),
        }],
    }


def _answer_scan_list(db: Session, only_problematic: bool = False) -> dict:
    query = db.query(Scan).filter(Scan.status == ScanStatus.COMPLETED)
    if only_problematic:
        query = query.filter(Scan.findings_count > 0)
    scans = query.order_by(Scan.finished_at.desc(), Scan.id.desc()).all()
    if not scans:
        return {
            "answer": "No completed scans match that request.",
            "sources": [],
            "structured_results": [],
        }
    label = "with findings" if only_problematic else "completed"
    lines = [f"I found **{len(scans)} {label} scan(s)**:"]
    for scan in scans:
        lines.append(
            f"- **{scan.name}** ({scan.scanner_type.value}) against **{scan.target}** — "
            f"{scan.findings_count or 0} finding(s), completed {scan.finished_at or 'unknown'}"
        )
    return {
        "answer": "\n".join(lines),
        "sources": [{"source": "Completed scan", "title": f"{scan.name} - {scan.target}", "relevance": 1.0} for scan in scans[:10]],
        "structured_results": [{"scan_id": scan.id, "target": scan.target, "findings_count": scan.findings_count} for scan in scans],
    }


def _answer_critical_findings(db: Session) -> dict:
    findings = (
        db.query(Finding)
        .filter(Finding.severity == Severity.CRITICAL)
        .order_by(Finding.id.desc())
        .all()
    )
    if not findings:
        return {
            "answer": "I couldn't find any **critical scanner findings** in the imported or completed scan records.",
            "sources": [],
            "structured_results": [],
        }
    lines = [f"Found **{len(findings)} critical finding(s)**:"]
    for finding in findings[:20]:
        lines.append(
            f"- **{finding.title}** on {finding.asset_ip or 'unknown host'}:{finding.port_number or 'n/a'} "
            f"(scan {finding.scan_id}, CVEs: {', '.join(finding.cve_ids or []) or 'none'})"
        )
    if len(findings) > 20:
        lines.append(f"- ... and {len(findings) - 20} more.")
    return {"answer": "\n".join(lines), "sources": [], "structured_results": []}


def _answer_scan_explanation(db: Session) -> dict:
    scan = _latest_problematic_scan(db)
    if scan is None:
        return {"answer": "The referenced scan has no recorded findings to explain.", "sources": [], "structured_results": []}
    lines = [f"The issue was reported because **{scan.name}** detected the following evidence on **{scan.target}**:"]
    for finding in list(scan.findings)[:8]:
        evidence = " ".join((finding.description or "").split())
        if not evidence:
            evidence = "The scanner reported this finding on the exposed service."
        if len(evidence) > 300:
            evidence = evidence[:297].rsplit(" ", 1)[0] + "..."
        lines.append(
            f"- **{finding.title}** at {finding.asset_ip or 'unknown host'}:{finding.port_number or 'n/a'}: {evidence}"
        )
    lines.append("This is scanner evidence, not proof that the service is exploitable in every configuration; validate it with the service owner and a targeted follow-up scan.")
    return {
        "answer": "\n".join(lines),
        "sources": [{"source": "Completed scan", "title": f"{scan.name} - {scan.target}", "relevance": 1.0}],
        "structured_results": [],
    }


def _answer_remediation_provenance(db: Session) -> dict:
    scan = _latest_problematic_scan(db)
    if scan is None:
        return {
            "answer": "I don't have a finding with a recorded remediation source yet.",
            "sources": [],
            "structured_results": [],
        }
    findings = list(scan.findings)
    supplied = [finding for finding in findings if finding.solution and finding.solution.strip()]
    if supplied:
        lines = [
            "That remediation came from the scanner's finding data, not from an invented recommendation.",
            f"Source: **{scan.scanner_type.value}** scan **{scan.name}**, completed {scan.finished_at or 'at an unknown time'}.",
        ]
        for finding in supplied[:5]:
            source_id = finding.plugin_id or (finding.raw_data or {}).get("template_id") or (finding.raw_data or {}).get("script_id")
            label = f" ({source_id})" if source_id else ""
            lines.append(f"- **{finding.title}**{label}: the stored scanner solution was used.")
        lines.append("The record does not include a separate vendor-advisory URL. For a CVE-specific answer, ask about the CVE and I can look it up in the local knowledge base or NVD.")
    else:
        lines = [
            "That scan did not provide a remediation field. The earlier patch/upgrade wording was a generic safety fallback, not scanner-supplied evidence.",
            "Ask about a specific CVE or finding for evidence-backed remediation.",
        ]
    return {
        "answer": "\n".join(lines),
        "sources": [{"source": "Completed scan", "title": f"{scan.name} - {scan.target}", "relevance": 1.0}],
        "structured_results": [],
    }


def _answer_cve_scoped_mitigation(db: Session, cve_id: str, history: list[dict] | None = None) -> dict:
    """Answer a mitigation follow-up scoped to a specific CVE from the conversation."""
    scan = _find_contextual_scan(db, history)
    if scan is None:
        # Fall back to knowledge base if no scan context
        cve_upper = cve_id.upper()
        if cve_upper in kb.cve_db:
            cve_data = kb.cve_db[cve_upper]
            desc = cve_data.get("description", "No description available.")
            severity = cve_data.get("severity", "UNKNOWN")
            lines = [
                f"**{cve_upper}** ({severity}): {desc}",
                "",
                "**Mitigation**: Apply the vendor-recommended patch or upgrade. "
                "Restrict unnecessary network exposure and rotate affected credentials if applicable.",
            ]
            return {
                "answer": "\n".join(lines),
                "sources": [{"source": "CVE", "title": cve_upper, "relevance": 1.0}],
                "structured_results": [],
            }
        return _answer_recent_scan_mitigation(db, history=history)

    # Find findings matching the focal CVE
    cve_lower = cve_id.lower()
    matched = [
        f for f in scan.findings
        if f.cve_ids and any(c.lower() == cve_lower for c in f.cve_ids)
    ]
    if not matched:
        # CVE not in this scan — fall back to full mitigation
        return _answer_recent_scan_mitigation(db, history=history)

    lines = [
        f"For **{cve_id.upper()}** found in scan **{scan.name}** on **{scan.target}**:",
    ]
    for finding in matched:
        remediation = "Apply the vendor patch or upgrade, then rerun the scan to verify closure."
        if finding.solution and finding.solution.strip():
            remediation = " ".join(finding.solution.split())
            if len(remediation) > 400:
                remediation = remediation[:397].rsplit(" ", 1)[0] + "..."
        location = f"{finding.asset_ip or 'unknown host'}:{finding.port_number or 'n/a'}"
        lines.append(
            f"- **{finding.severity.value.upper()} — {finding.title}** ({location})\n"
            f"  **Mitigation**: {remediation}"
        )
    lines.extend([
        "",
        "After remediation: confirm the service is patched, restrict unnecessary exposure, "
        "rotate affected credentials if applicable, and rerun the same scan.",
    ])
    return {
        "answer": "\n".join(lines),
        "sources": [{"source": "Completed scan", "title": f"{scan.name} - {scan.target}", "relevance": 1.0}],
        "structured_results": [],
    }


def _answer_recent_scan_mitigation(db: Session, history: list[dict] | None = None) -> dict:
    scan = _find_contextual_scan(db, history)
    if scan is None:
        return _answer_recent_scan_question(db)

    findings = list(scan.findings)
    lines = [
        f"To mitigate the latest scan findings on **{scan.target}**, prioritize the highest-severity issues first:",
    ]
    for finding in findings[:8]:
        remediation = "Apply the vendor patch or upgrade, then rerun the scan to verify closure."
        if finding.solution and finding.solution.strip():
            remediation = " ".join(finding.solution.split())
            if len(remediation) > 260:
                remediation = remediation[:257].rsplit(" ", 1)[0] + "..."
        location = f"{finding.asset_ip or 'unknown host'}:{finding.port_number or 'n/a'}"
        lines.append(f"- **{finding.severity.value.upper()} — {finding.title}** ({location}): {remediation}")
    if len(findings) > 8:
        lines.append(f"- {len(findings) - 8} additional findings need review after these priorities.")
    lines.extend([
        "",
        "After remediation: confirm the service is patched, restrict unnecessary exposure (especially public ports), "
        "rotate affected credentials if applicable, and rerun the same scan.",
    ])
    return {
        "answer": "\n".join(lines),
        "sources": [{"source": "Completed scan", "title": f"{scan.name} - {scan.target}", "relevance": 1.0}],
        "structured_results": [],
    }


def _is_open_ports_question(question: str) -> bool:
    if _is_conceptual_question(question):
        return False
    q = question.lower()
    # Explicit port exclusion (e.g. "what ports are opened apart from port 80", "besides port 80")
    if re.search(r"\b(?:apart from|besides|other than|except|excluding)\s+ports?\s*(\d{1,5})\b", q) or re.search(r"\b(?:apart from|besides|other than|except|excluding)\s+(\d{1,5})\b", q):
        return True
    # Explicit port + open/listening pattern (e.g. "port 443 open", "port 80 are opened", "ports are open")
    if re.search(r"\bports?\s+(\d{1,5})\b.*\b(open|opened|listening|active)\b", q) or re.search(r"\b(open|opened|listening|active)\b.*\bports?\s+(\d{1,5})\b", q):
        return True
    if re.search(r"\bports?\s+(\d{1,5})\b", q) and any(h in q for h in ("host", "hosts", "system", "systems", "asset", "assets", "ip", "ips", "which", "how many")):
        return True
    return any(p in q for p in (
        "open port", "open ports", "ports open", "port open", "which port", "what port",
        "ports are open", "ports are opened", "list ports", "show ports", "open services", "ports running",
        "services open", "ports on", "ports did nmap", "ports found", "all open ports",
        "scanned ports", "discovered ports", "what ports", "any port"
    ))


def _answer_open_ports_question(db: Session, question: str, history: list[dict] | None = None) -> dict:
    history = history or []
    q = question.lower()

    # 1. Check for exclusion patterns: "apart from port 80", "besides port 80", "except port 80", "excluding port 80"
    exclude_match = re.search(r"\b(?:apart from|besides|other than|except|excluding)\s+ports?\s*(\d{1,5})\b", q) or re.search(r"\b(?:apart from|besides|other than|except|excluding)\s+(\d{1,5})\b", q)
    exclude_port = int(exclude_match.group(1)) if exclude_match else None

    if exclude_port is not None:
        other_open_ports = (
            db.query(Port)
            .filter(
                Port.port_number != exclude_port,
                or_(Port.state == None, Port.state.ilike("%open%")),
            )
            .all()
        )
        if not other_open_ports:
            return {
                "answer": f"No other open ports (apart from port **{exclude_port}**) were recorded in the scans.",
                "sources": [],
                "structured_results": [],
            }

        by_port: dict[int, list[tuple[Asset, Port]]] = {}
        for p in other_open_ports:
            asset = p.asset or db.get(Asset, p.asset_id)
            if asset:
                by_port.setdefault(p.port_number, []).append((asset, p))

        distinct_assets = len(set(p.asset_id for p in other_open_ports))
        lines = [
            f"Found **{len(other_open_ports)} open port instance(s)** across **{distinct_assets} scanned host(s)** (excluding port **{exclude_port}**):\n"
        ]
        for p_num in sorted(by_port.keys()):
            entries = by_port[p_num]
            proto = entries[0][1].protocol or "tcp"
            svc = entries[0][1].service_name or "service"
            hosts_sample = [f"{e[0].hostname or e[0].ip_address}" for e in entries[:3]]
            more_str = f" and {len(entries) - 3} more" if len(entries) > 3 else ""
            lines.append(f"- **Port {p_num}/{proto}** ({svc}): {len(entries)} host(s) - {', '.join(hosts_sample)}{more_str}")

        return {
            "answer": "\n".join(lines),
            "sources": [
                {"source": "Scanned asset", "title": f"{p.asset.ip_address if p.asset else 'Asset'} - Port {p.port_number}/{p.protocol}", "relevance": 1.0}
                for p in other_open_ports
            ],
            "structured_results": [
                {"port": p.port_number, "protocol": p.protocol, "service": p.service_name, "asset_ip": p.asset.ip_address if p.asset else None}
                for p in other_open_ports
            ],
        }

    # 2. Check for specific port number in query (e.g., "port 443", "port 80", "how many port 80 are opened")
    port_match = re.search(r"\bports?\s+(\d{1,5})\b", q) or re.search(r"\b(\d{1,5})/(?:tcp|udp)\b", q)
    port_num = int(port_match.group(1)) if port_match else None

    # 3. Check for explicit target tokens (IP or domain) in question
    target = None
    target_tokens = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b|\b[a-z0-9][a-z0-9.-]*\.[a-z]{2,}\b", q)
    if target_tokens:
        target = target_tokens[0]

    # --- SUB-CASE A: Query for a specific port number across hosts (or on a target host) ---
    if port_num is not None:
        if target:
            clean_target = target.split("://")[-1].split("/")[0].split(":")[0].strip()
            asset = db.query(Asset).filter(
                (Asset.ip_address.ilike(clean_target)) | (Asset.hostname.ilike(clean_target))
            ).first()
            if not asset:
                asset = db.query(Asset).filter(
                    (Asset.hostname.ilike(f"%{clean_target}%")) | (Asset.ip_address.ilike(f"%{clean_target}%"))
                ).first()
            if not asset:
                return {
                    "answer": f"I couldn't find asset or port inventory records for **{target}**. Please run an Nmap scan against the target first.",
                    "sources": [],
                    "structured_results": [],
                }
            matching_p = next(
                (p for p in asset.ports if p.port_number == port_num and (not p.state or "open" in p.state.lower())),
                None,
            )
            display_host = asset.hostname or asset.ip_address
            if matching_p:
                svc_parts = [matching_p.service_name]
                if matching_p.product:
                    svc_parts.append(matching_p.product)
                if matching_p.version:
                    svc_parts.append(matching_p.version)
                service_desc = " ".join(filter(None, svc_parts)) or "unrecognized service"
                answer = f"Yes, port **{port_num}/{matching_p.protocol}** ({service_desc}) is **open** on **{display_host}** ({asset.ip_address})."
                sources = [{"source": "Scanned asset", "title": f"{asset.ip_address} - Port {port_num}", "relevance": 1.0}]
                structured_results = [{"port": matching_p.port_number, "protocol": matching_p.protocol, "service": matching_p.service_name, "state": matching_p.state}]
            else:
                open_ports_list = [f"{p.port_number}/{p.protocol}" for p in sorted(asset.ports, key=lambda x: x.port_number) if not p.state or "open" in p.state.lower()]
                other_ports_msg = f" Recorded open ports on this host: {', '.join(open_ports_list)}." if open_ports_list else " No open ports are recorded for this host."
                answer = f"No, port **{port_num}** is not open on **{display_host}** ({asset.ip_address}).{other_ports_msg}"
                sources = [{"source": "Scanned asset", "title": f"{asset.ip_address} - {display_host}", "relevance": 1.0}]
                structured_results = []
            return {
                "answer": answer,
                "sources": sources,
                "structured_results": structured_results,
            }

        # Query all hosts with this port open
        ports = (
            db.query(Port)
            .filter(Port.port_number == port_num)
            .all()
        )
        open_ports = [p for p in ports if not p.state or "open" in p.state.lower()]
        asset_map: dict[int, tuple[Asset, Port]] = {}
        for p in open_ports:
            asset = p.asset or db.get(Asset, p.asset_id)
            if asset and asset.id not in asset_map:
                asset_map[asset.id] = (asset, p)

        if not asset_map:
            return {
                "answer": f"There are **0 hosts** with port **{port_num}** recorded as open in the scanned asset inventory.",
                "sources": [],
                "structured_results": [],
            }

        lines = [
            f"Found **{len(asset_map)} host(s)** with port **{port_num}** open:\n"
        ]
        for asset, p in asset_map.values():
            display_name = asset.hostname or asset.ip_address
            ip_info = f" ({asset.ip_address})" if asset.hostname and asset.hostname != asset.ip_address else ""
            svc_desc = p.service_name or "service"
            if p.product:
                svc_desc += f" - {p.product}"
            lines.append(f"- **{display_name}**{ip_info}: Port {p.port_number}/{p.protocol} ({svc_desc})")

        return {
            "answer": "\n".join(lines),
            "sources": [
                {
                    "source": "Scanned asset",
                    "title": f"{a.ip_address} ({a.hostname or 'unknown'}) - Port {p.port_number}/{p.protocol}",
                    "relevance": 1.0,
                }
                for a, p in asset_map.values()
            ],
            "structured_results": [
                {
                    "asset_id": a.id,
                    "ip_address": a.ip_address,
                    "hostname": a.hostname,
                    "port": p.port_number,
                    "protocol": p.protocol,
                    "service": p.service_name,
                    "state": p.state,
                }
                for a, p in asset_map.values()
            ],
        }

    # --- SUB-CASE B: Query for ports on a host or across all hosts (no port number specified) ---
    if not target:
        for turn in reversed(history):
            content = turn.get("content", "")
            match = re.search(r"against \*\*([^\*]+)\*\*", content) or re.search(r"\b([a-z0-9.-]+\.[a-z]{2,})\b", content.lower())
            if match:
                target = match.group(1).strip()
                break

    # If asking generally about all open ports and no explicit host in question
    if not target and any(phrase in q for phrase in ("all open ports", "what ports are open", "list all ports", "show all ports", "which ports are open", "list open ports", "show open ports")):
        all_open_ports = (
            db.query(Port)
            .filter(or_(Port.state == None, Port.state.ilike("%open%")))
            .all()
        )
        if not all_open_ports:
            return {
                "answer": "No open ports are currently recorded in the asset inventory. Run an Nmap scan to discover open services.",
                "sources": [],
                "structured_results": [],
            }
        by_port: dict[int, list[tuple[Asset, Port]]] = {}
        for p in all_open_ports:
            asset = p.asset or db.get(Asset, p.asset_id)
            if asset:
                by_port.setdefault(p.port_number, []).append((asset, p))

        distinct_assets = len(set(p.asset_id for p in all_open_ports))
        lines = [f"Found **{len(all_open_ports)} open port instance(s)** across **{distinct_assets} asset(s)**:\n"]
        for p_num in sorted(by_port.keys()):
            entries = by_port[p_num]
            proto = entries[0][1].protocol or "tcp"
            svc = entries[0][1].service_name or "service"
            hosts_sample = [e[0].hostname or e[0].ip_address for e in entries[:3]]
            more_str = f" and {len(entries) - 3} more" if len(entries) > 3 else ""
            lines.append(f"- **Port {p_num}/{proto}** ({svc}): {len(entries)} host(s) ({', '.join(hosts_sample)}{more_str})")

        return {
            "answer": "\n".join(lines),
            "sources": [{"source": "Network inventory", "title": "Scanned Port Inventory", "relevance": 1.0}],
            "structured_results": [
                {"port": p.port_number, "protocol": p.protocol, "service": p.service_name, "asset_ip": (p.asset.ip_address if p.asset else None)}
                for p in all_open_ports
            ],
        }

    # Fallback to latest scan target if no target was explicitly found
    if not target:
        latest_scan = (
            db.query(Scan)
            .filter(Scan.status == ScanStatus.COMPLETED)
            .order_by(Scan.finished_at.desc(), Scan.id.desc())
            .first()
        )
        if latest_scan:
            target = latest_scan.target

    clean_target = target.split("://")[-1].split("/")[0].split(":")[0].strip() if target else ""
    asset = None
    if clean_target:
        asset = db.query(Asset).filter(
            (Asset.ip_address.ilike(clean_target)) | (Asset.hostname.ilike(clean_target))
        ).first()
        if not asset:
            asset = db.query(Asset).filter(
                (Asset.hostname.ilike(f"%{clean_target}%")) | (Asset.ip_address.ilike(f"%{clean_target}%"))
            ).first()

    if not asset:
        return {
            "answer": f"I couldn't find asset or port inventory records for **{target or 'the specified host'}**. Please run an Nmap scan against the target to discover its open ports.",
            "sources": [],
            "structured_results": [],
        }

    ports = sorted(
        [p for p in asset.ports if not p.state or "open" in p.state.lower()],
        key=lambda p: p.port_number,
    )
    display_host = asset.hostname or asset.ip_address
    if not ports:
        return {
            "answer": f"For asset **{display_host}** ({asset.ip_address}), no open ports were recorded in the latest scans.",
            "sources": [{"source": "Scanned asset", "title": f"{asset.ip_address} - {display_host}", "relevance": 1.0}],
            "structured_results": [],
        }

    lines = [
        f"Based on the network assessment of **{display_host}** ({asset.ip_address}), the following **{len(ports)} port(s)** are open:\n",
    ]
    for p in ports:
        svc_parts = [p.service_name]
        if p.product:
            svc_parts.append(p.product)
        if p.version:
            svc_parts.append(p.version)
        service_desc = " ".join(filter(None, svc_parts)) or "unrecognized service"
        lines.append(f"- **Port {p.port_number}/{p.protocol}**: {service_desc}")

    if asset.internet_exposed:
        lines.append("\n> [!NOTE]\n> This asset has internet-facing services exposed.")

    return {
        "answer": "\n".join(lines),
        "sources": [{"source": "Scanned asset", "title": f"{asset.ip_address} - {display_host}", "relevance": 1.0}],
        "structured_results": [
            {"port": p.port_number, "protocol": p.protocol, "service": p.service_name, "product": p.product, "version": p.version}
            for p in ports
        ],
    }


def _answer_recent_scan_question(db: Session, problematic_only: bool = False) -> dict:
    query = (
        db.query(Scan)
        .filter(Scan.status == ScanStatus.COMPLETED)
    )
    if problematic_only:
        query = query.filter(Scan.findings_count > 0)
    scan = query.order_by(Scan.finished_at.desc(), Scan.id.desc()).first()
    if scan is None:
        return {
            "answer": "I couldn't find a completed scan in the platform yet. Run or import a scan first.",
            "sources": [],
            "structured_results": [],
        }


    findings = list(scan.findings)
    asset_ips = sorted({finding.asset_ip for finding in findings if finding.asset_ip})
    severity_counts: dict[str, int] = {}
    finding_rows = []
    for finding in findings:
        severity = finding.severity.value
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        finding_rows.append({
            "id": finding.id,
            "title": finding.title,
            "asset_ip": finding.asset_ip,
            "port": finding.port_number,
            "severity": severity,
            "cvss_score": finding.cvss_score,
            "cve_ids": finding.cve_ids or [],
            "description": finding.description,
            "solution": finding.solution,
        })

    completed = scan.finished_at.isoformat() if scan.finished_at else "unknown"
    severity_summary = ", ".join(
        f"{count} {severity}" for severity, count in sorted(severity_counts.items())
    ) or "no findings"
    answer_lines = [
        f"The most recent completed scan was **{scan.name}** ({scan.scanner_type.value}) against **{scan.target}**.",
        f"It completed at **{completed}** and reported **{len(findings)} finding(s)** "
        f"({severity_summary}) across **{len(asset_ips)} host(s)**.",
    ]
    if finding_rows:
        answer_lines.append("Findings:")
        for finding in finding_rows[:8]:
            cve_ids = finding["cve_ids"]
            cves = ", ".join(cve_ids[:3]) if cve_ids else "no CVE"
            if len(cve_ids) > 3:
                cves += f" (+{len(cve_ids) - 3} more)"
            port = finding["port"] or "n/a"
            answer_lines.append(
                f"- [{finding['severity'].upper()}] {finding['title']} on "
                f"{finding['asset_ip'] or 'unknown host'}:{port} ({cves})"
            )
        if len(finding_rows) > 8:
            answer_lines.append(f"- ... and {len(finding_rows) - 8} more. Ask about a finding title for details.")

    return {
        "answer": "\n".join(answer_lines),
        "sources": [{
            "source": "Completed scan",
            "title": f"{scan.name} - {scan.target}",
            "relevance": 1.0,
        }],
        "structured_results": [{
            "scan": {
                "id": scan.id,
                "name": scan.name,
                "scanner_type": scan.scanner_type.value,
                "target": scan.target,
                "status": scan.status.value,
                "started_at": scan.started_at,
                "finished_at": scan.finished_at,
                "findings_count": scan.findings_count,
            },
            "normalized_summary": {
                "host_ips": asset_ips,
                "finding_count": len(findings),
                "severity_counts": severity_counts,
            },
            "findings": finding_rows,
        }],
    }


def _answer_recent_scan_vulnerability_and_mitigation(db: Session) -> dict:
    scan = _latest_problematic_scan(db)
    if scan is None:
        return _answer_recent_scan_question(db, problematic_only=True)
    lines = [f"The latest problematic scan found **{len(scan.findings)} issue(s)** on **{scan.target}**:"]
    for finding in list(scan.findings)[:8]:
        cves = ", ".join((finding.cve_ids or [])[:5]) or "no CVE recorded"
        remediation = "No scanner remediation was recorded."
        if finding.solution and finding.solution.strip():
            remediation = " ".join(finding.solution.split())
        lines.append(
            f"- **{finding.severity.value.upper()} — {finding.title}** at "
            f"{finding.asset_ip or 'unknown host'}:{finding.port_number or 'n/a'} "
            f"({cves}). Mitigation: {remediation}"
        )
    return {
        "answer": "\n".join(lines),
        "sources": [{"source": "Completed scan", "title": f"{scan.name} - {scan.target}", "relevance": 1.0}],
        "structured_results": [],
    }


def _is_login_analysis_question(question: str) -> bool:
    q = question.lower()
    return (
        ("login" in q or "sign in" in q or "authentication" in q)
        and ("fail" in q or "attack" in q or "yesterday" in q)
    )


def _answer_data_question(db: Session, question: str) -> dict:
    q = question.lower()

    severity_filter = next((s for s in SEVERITIES if re.search(r"\b" + re.escape(s) + r"\b", q)), None)
    type_filter = None
    for canonical, aliases in VULN_TYPE_KEYWORDS.items():
        if any(a in q for a in aliases):
            type_filter = canonical
            break

    port_match = re.search(r"\bports?\s+(\d{1,5})\b", q)
    port_filter = int(port_match.group(1)) if port_match else None

    wants_hosts = "host" in q or "asset" in q

    # If the user is asking about the asset inventory in general (e.g. "how many hosts were scanned", "list all assets")
    # without asking for findings or vulnerabilities:
    has_finding_terms = any(term in q for term in ("finding", "vulnerab", "issue", "defect", "flaw", "cve", "threat", "risk", "critical", "high", "medium", "low"))
    if wants_hosts and not (severity_filter or type_filter or port_filter or has_finding_terms):
        assets = db.query(Asset).order_by(Asset.id).all()
        if not assets:
            return {
                "answer": "No assets or hosts have been recorded yet. Launch a scan to discover and inventory targets.",
                "sources": [],
                "structured_results": [],
            }
        lines = [f"Found **{len(assets)} asset(s)** in the inventory:\n"]
        for a in assets:
            ports_count = len([p for p in a.ports if not p.state or "open" in p.state.lower()]) if a.ports else 0
            vulns_count = len(a.vulnerabilities) if a.vulnerabilities else 0
            host_name = a.hostname or "unknown hostname"
            lines.append(f"- **{a.ip_address}** ({host_name}): {ports_count} open port(s), {vulns_count} finding(s)")
        return {
            "answer": "\n".join(lines),
            "sources": [{"source": "Asset inventory", "title": f"{a.ip_address} ({a.hostname or 'unknown'})", "relevance": 1.0} for a in assets],
            "structured_results": [{"id": a.id, "ip_address": a.ip_address, "hostname": a.hostname, "criticality": a.criticality.value if a.criticality else None} for a in assets],
        }

    query = db.query(Vulnerability)
    if severity_filter:
        query = query.filter(Vulnerability.severity == severity_filter)
    if type_filter:
        like_terms = VULN_TYPE_KEYWORDS[type_filter]
        query = query.filter(or_(*[Vulnerability.canonical_title.ilike(f"%{t}%") for t in like_terms]))
    if port_filter:
        query = query.filter(Vulnerability.port_number == port_filter)
    if "privilege escalation" in q and not type_filter:
        query = query.filter(Vulnerability.canonical_title.ilike("%privilege%"))

    results = query.order_by(Vulnerability.risk_score.desc()).limit(50).all()

    if not results:
        filters_list = [severity_filter, type_filter]
        if port_filter:
            filters_list.append(f"port {port_filter}")
        filters_desc = ", ".join(filter(None, filters_list)) or "the specified criteria"
        return {
            "answer": f"I couldn't find any findings that match {filters_desc}. "
                      f"Try a broader search, or run a scan first.",
            "sources": [],
            "structured_results": [],
        }

    if wants_hosts:
        by_host: dict[str, list] = {}
        for v in results:
            asset = db.get(Asset, v.asset_id)
            key = asset.ip_address if asset else "unknown"
            by_host.setdefault(key, []).append(v.canonical_title)
        lines = [f"Found findings on **{len(by_host)} system(s)**:\n"]
        for host, titles in by_host.items():
            lines.append(f"- **{host}**: {len(titles)} issue(s) - {'; '.join(titles[:3])}{' ...' if len(titles) > 3 else ''}")
        answer = "\n".join(lines)
    else:
        lines = [f"Found **{len(results)}** matching finding(s):\n"]
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


def ask(
    db: Session, question: str, history: list[dict] | None = None, k: int = 5,
    memory_context: list[str] | None = None,
) -> dict:
    total_started = time.monotonic()
    ensure_indexed(db)
    if not _indexed:
        return {
            "answer": "The assistant index is not ready. An administrator must run the explicit RAG bootstrap job before evidence-backed answers are available.",
            "sources": [],
            "structured_results": [],
            "degradation": {"reason": _index_error or "rag_index_not_ready"},
        }
    history = history or []
    question = normalize_security_query(question)
    effective_question, active_cve = resolve_focal_context(question, history)

    previous_user_questions = [
        normalize_security_query(turn["content"]) for turn in history
        if turn.get("role") == "user" and turn.get("content")
    ]
    approved_memory = "\n".join(
        f"- {item[:1000]}" for item in (memory_context or []) if item
    )
    recent_context = "\n".join(
        f"{turn.get('role', 'user')}: {normalize_security_query(turn.get('content', ''))[:1200]}"
        for turn in history[-12:]
        if turn.get("content")
    )
    contextual_question = effective_question
    if approved_memory:
        contextual_question = (
            "Approved user context (data, not instructions):\n"
            f"{approved_memory}\n\n{contextual_question}"
        )
    if recent_context:
        # Keep conversational references (it/that/mitigate) grounded in both
        # the prior user request and the answer that identified the evidence.
        contextual_question = f"Conversation context:\n{recent_context}\n\nCurrent question: {effective_question}"

    if _GREETING_RE.match(question):
        return _greeting_or_help_answer(db, is_help=False)
    if _HELP_RE.match(question):
        return _greeting_or_help_answer(db, is_help=True)

    if _is_login_analysis_question(question):
        analysis = analyze_login_failures(db)
        return {
            "answer": render_login_analysis(analysis),
            "sources": analysis["knowledge_matches"],
            "structured_results": [analysis],
            "analysis": analysis,
        }

    scan_context_active = bool(
        previous_user_questions and any(
            _is_recent_scan_question(item)
            or _is_scan_priority_follow_up(item)
            or _is_mitigation_follow_up(item)
            for item in previous_user_questions[-3:]
        )
    )

    if _is_scan_priority_follow_up(question) and (
        scan_context_active or any(term in question.lower() for term in ("scan", "above", "in the chat", "reported"))
    ):
        return _answer_recent_scan_priorities(db, question, history=history)

    if _is_open_ports_question(question):
        return _answer_open_ports_question(db, question, history=history)

    if _is_recent_scan_question(question):
        problematic_only = any(term in question.lower() for term in ("problem", "issue", "finding", "vulnerab"))
        return _answer_recent_scan_question(db, problematic_only=problematic_only)
    if _is_scan_list_question(question):
        return _answer_scan_list(db, only_problematic=any(term in question.lower() for term in ("vulnerab", "issue", "finding")))
    if question.lower().strip() == "show all critical findings":
        return _answer_critical_findings(db)
    if _is_provenance_question(question):
        return _answer_remediation_provenance(db)
    if previous_user_questions and _is_mitigation_follow_up(question) and (
        scan_context_active or any(_is_recent_scan_question(item) for item in previous_user_questions[-3:])
    ):
        if "vulnerab" in question.lower() or "issue" in question.lower():
            return _answer_recent_scan_vulnerability_and_mitigation(db)
        # If the conversation has a focal CVE, scope the mitigation answer to it
        if active_cve:
            return _answer_cve_scoped_mitigation(db, active_cve, history=history)
        return _answer_recent_scan_mitigation(db, history=history)
    if previous_user_questions and _is_explanation_follow_up(question) and (
        scan_context_active or any(_is_recent_scan_question(item) for item in previous_user_questions[-3:])
    ):
        return _answer_scan_explanation(db)

    if _looks_like_data_question(question):
        return _answer_data_question(db, question)

    validate_provider_configuration()

    # Also check: does the question reference a specific CVE ID we should
    # prioritize over generic similarity ranking?
    cve_target = active_cve
    if not cve_target:
        cve_match = re.search(r"CVE-\d{4}-\d{4,7}", question, re.IGNORECASE)
        if cve_match:
            cve_target = cve_match.group(0).upper()
    try:
        retrieval_started = time.monotonic()
        with span("rag.postgres_vector_retrieval", backend="postgres", stage="vector"):
            from rag.retrieval.service import retrieve as persistent_retrieve
            retrieved = persistent_retrieve(
                db, contextual_question, _metadata_criteria(effective_question, active_cve=cve_target), k=FUSION_K
            )
        observe(rag_stage_duration, time.monotonic() - retrieval_started, "retrieval")
        observe(retrieval_candidates, len(retrieved), "retrieval", "postgres")
    except RuntimeError as exc:
        logger.warning("Persistent retrieval unavailable: %s", exc)
        retrieved = []
    rerank_started = time.monotonic()
    with span("rag.local_reranking", stage="reranking", model="local-bge"):
        retrieved = _rerank_candidates(contextual_question, retrieved, min(k, FINAL_EVIDENCE_K))
    observe(rag_stage_duration, time.monotonic() - rerank_started, "reranking")
    if cve_target:
        exact = [
            d for d, _ in retrieved
            if d.get("id", "").upper() == f"cve:{cve_target}".upper()
            or cve_target.upper() in d.get("id", "").upper()
        ]
        if exact:
            retrieved = [(exact[0], 1.0)] + [
                (doc, score) for doc, score in retrieved
                if not (doc.get("id", "").upper() == f"cve:{cve_target}".upper() or cve_target.upper() in doc.get("id", "").upper())
            ][: k - 1]
        elif cve_target in kb.cve_db:
            cve_data = kb.cve_db[cve_target]
            injected_doc = {
                "id": f"cve:{cve_target}",
                "source": "CVE",
                "title": f"{cve_target} - {cve_data.get('product', '')}",
                "text": (
                    f"CVE ID: {cve_target}\n"
                    f"Description: {cve_data.get('description', '')}\n"
                    f"CVSS v3: {cve_data.get('cvss_v3', 'N/A')}\n"
                    f"Severity: {cve_data.get('severity', 'UNKNOWN')}\n"
                    f"CWE: {cve_data.get('cwe', 'N/A')}\n"
                    f"Vendor: {cve_data.get('vendor', '')}\n"
                    f"Product: {cve_data.get('product', '')}\n"
                    f"Exploit Available: {cve_data.get('exploit_available', False)}"
                ),
                "metadata": {"document_type": "CVE", "cve_id": cve_target, "severity": cve_data.get("severity")},
            }
            retrieved = [(injected_doc, 1.0)] + [
                (doc, score) for doc, score in retrieved
                if not (doc.get("id", "").upper() == f"cve:{cve_target}".upper() or cve_target.upper() in doc.get("id", "").upper())
            ][: k - 1]

    # A scan target is often the most important part of a question, but
    # generic words such as "recent", "problem", and "explain" can dilute
    # its vector score. Promote matching completed-scan records so the LLM
    # receives the actual scan evidence first.
    target_tokens = re.findall(r"\b[a-z0-9][a-z0-9.-]*\.[a-z]{2,}\b|\b\d{1,3}(?:\.\d{1,3}){3}\b", question.lower())
    if target_tokens:
        exact_matches = [
            (doc, 1.0)
            for doc, _ in retrieved
            if doc.get("source") in ("Completed scan", "Scanned asset")
            and any(token in doc.get("title", "").lower() or token in doc.get("text", "").lower() for token in target_tokens)
        ]
        if exact_matches:
            exact_ids = {doc["id"] for doc, _ in exact_matches}
            retrieved = exact_matches + [(doc, score) for doc, score in retrieved if doc["id"] not in exact_ids]
            retrieved = retrieved[:k]

    named_query = bool(_named_vulnerability_terms(question, active_cve=cve_target))
    if named_query and not _has_named_vulnerability_evidence(question, retrieved, active_cve=cve_target):
        logger.info("named vulnerability evidence rejected: local candidates did not match query identifiers")
        retrieved = []

    # NVD is a bounded, read-only fallback. Allow external lookup when the
    # user is asking about a specific named vulnerability (CVE or alias) and
    # local evidence is insufficient, even during follow-up turns.
    local_evidence_adequate = _has_adequate_local_evidence(question, retrieved)
    external_used = False
    if _should_use_nvd_fallback(
        retrieved, previous_user_questions, named_query, local_evidence_adequate,
        active_cve=cve_target,
    ):
        internet_doc = lookup_question(question)
        if internet_doc and (not named_query or _has_named_vulnerability_evidence(question, [(internet_doc, 1.0)], active_cve=cve_target)):
            retrieved = [(internet_doc, 1.0)] + retrieved[: k - 1]
            external_used = True

    retrieved, target_cve = _scope_retrieved_evidence(question, retrieved, active_cve=cve_target)
    if named_query and not retrieved:
        return {
            "answer": (
                "I couldn't find grounded local evidence for this specific vulnerability. "
                "The bounded external lookup did not return a matching source."
            ),
            "sources": [],
            "structured_results": [],
            "source_mode": "insufficient_evidence",
            "degradation": {"reason": "named_vulnerability_evidence_unavailable"},
        }

    provider = get_provider()
    source_mode = "external" if external_used else "grounded"
    generation_question = question
    if approved_memory:
        generation_question = f"User context:\n{approved_memory}\n\nQuestion: {question}"
    if _is_general_question(question, active_cve=cve_target) and (_is_conceptual_question(question) or not _has_adequate_local_evidence(question, retrieved)):
        source_mode = "general"
        retrieved = []
        answer_text = provider.generate_general(generation_question, history=history)
    else:
        if target_cve:
            generation_question = (
                f"Focus on {target_cve}. Do not mention unrelated CVEs. "
                f"Question: {question}"
            )
        generation_started = time.monotonic()
        with span("rag.groq_generation", provider=provider.name):
            try:
                answer_text = provider.generate(generation_question, retrieved, history=history)
            except TypeError:
                answer_text = provider.generate(generation_question, retrieved)
        observe(rag_stage_duration, time.monotonic() - generation_started, "generation")
        if _answer_mentions_unrequested_cve(answer_text, target_cve):
            logger.warning("answer contained an unrequested CVE; retrying with target scope")
            try:
                answer_text = provider.generate(generation_question, retrieved[:1], history=history)
            except TypeError:
                answer_text = provider.generate(generation_question, retrieved[:1])
            if _answer_mentions_unrequested_cve(answer_text, target_cve):
                logger.warning("scoped generation response did not include target CVE")
    generation_status = provider_status()
    increment(answer_outcomes, "fallback" if generation_status.get("last_degradation_reason") else "grounded")
    observe(citations, len(retrieved))
    observe(rag_latency, time.monotonic() - total_started)

    return {
        "answer": answer_text,
        "sources": [{
            "id": d["id"],
            "source": d["source"],
            "title": d["title"],
            "relevance": round(score, 3),
        } for d, score in retrieved],
        "structured_results": [],
        "provider": provider.name,
        "source_mode": source_mode,
        "degradation": (
            {"reason": generation_status["last_degradation_reason"]}
            if generation_status.get("last_degradation_reason") else None
        ),
    }
