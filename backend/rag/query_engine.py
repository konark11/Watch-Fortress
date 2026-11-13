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

from models.database import Vulnerability, Finding, Asset, Scan, ScanStatus, Severity
from rag.retriever import HybridRetriever
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
    "log4shell": {"log4shell", "cve-2021-44228"},
    "heartbleed": {"heartbleed", "cve-2014-0160"},
    "shellshock": {"shellshock", "cve-2014-6271"},
    "proxylogon": {"proxylogon", "cve-2021-26855"},
    "printnightmare": {"printnightmare", "cve-2021-34527"},
    "dirty pipe": {"dirty pipe", "cve-2022-0847"},
    "eternalblue": {"eternalblue", "cve-2017-0144"},
    "bluekeep": {"bluekeep", "cve-2019-0708"},
}


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
        logger.warning("OpenRouter reranking unavailable: %s", exc)
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


def _metadata_filter(question: str):
    """Build pre-retrieval filters from explicit security metadata in a query."""
    lowered = question.lower()
    severity = next((value for value in SEVERITIES if value in lowered), None)
    port_match = re.search(r"\bport\s+(\d{1,5})\b", lowered)
    cve_match = re.search(r"\bcve-\d{4}-\d{4,7}\b", lowered, re.IGNORECASE)
    vm_match = re.search(
        r"\b(?:vm|host|asset|ip)\s+((?:\d{1,3}\.){3}\d{1,3})\b",
        lowered,
    )
    document_type = next((
        source for term, source in {
            "cve": "CVE", "cwe": "CWE", "capec": "CAPEC",
            "owasp": "OWASP", "mitre": "MITRE ATT&CK",
            "finding": "Scan finding", "scan": "Completed scan",
        }.items() if term in lowered
    ), None)
    if not any((severity, port_match, cve_match, vm_match, document_type)):
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
        if cve_match and cve_match.group(0).lower() not in text:
            return False
        if vm_match and vm_match.group(1) not in text:
            return False
        return True

    return matches


def _named_vulnerability_terms(question: str) -> set[str]:
    """Return identifiers that must be present in evidence for specific asks."""
    lowered = question.lower()
    terms: set[str] = set(re.findall(r"\bcve-\d{4}-\d{4,7}\b", lowered))
    known_match = False
    for name, aliases in _KNOWN_VULNERABILITY_ALIASES.items():
        if name in lowered:
            terms.update(aliases)
            known_match = True
    if terms or known_match:
        return terms
    words = re.findall(r"\b[A-Z][A-Za-z0-9.+-]{3,}\b", question)
    ignored = {"Explain", "What", "How", "Why", "Attack", "Vulnerability"}
    terms.update(word.lower() for word in words if word not in ignored)
    return terms


def _has_named_vulnerability_evidence(
    question: str,
    retrieved: list[tuple[dict, float]],
) -> bool:
    terms = _named_vulnerability_terms(question)
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
    if retrieved[0][1] >= 0.08:
        return True
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


def _should_use_nvd_fallback(
    retrieved: list[tuple[dict, float]],
    previous_user_questions: list[str],
    named_query: bool = False,
    local_evidence_adequate: bool = False,
) -> bool:
    return (
        (not retrieved or (
            retrieved[0][1] < 0.08
            and not named_query
            and not local_evidence_adequate
        ))
        and not previous_user_questions
    )


def _metadata_criteria(question: str) -> dict:
    lowered = question.lower()
    criteria: dict = {}
    severity = next((value for value in SEVERITIES if value in lowered), None)
    if severity:
        criteria["severity"] = severity
    port_match = re.search(r"\bport\s+(\d{1,5})\b", lowered)
    if port_match:
        criteria["port"] = int(port_match.group(1))
    cve_match = re.search(r"\bcve-\d{4}-\d{4,7}\b", lowered, re.IGNORECASE)
    if cve_match:
        criteria["cve"] = cve_match.group(0)
    vm_match = re.search(
        r"\b(?:vm|host|asset|ip)\s+((?:\d{1,3}\.){3}\d{1,3})\b",
        lowered,
    )
    if vm_match:
        criteria["vm"] = vm_match.group(1)
    criteria["document_type"] = next((
        source for term, source in {
            "cve": "CVE", "cwe": "CWE", "capec": "CAPEC",
            "owasp": "OWASP", "mitre": "MITRE ATT&CK",
            "finding": "Scan finding", "scan": "Completed scan",
        }.items() if term in lowered
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
    return (
        db.query(Scan)
        .filter(Scan.status == ScanStatus.COMPLETED, Scan.findings_count > 0)
        .order_by(Scan.finished_at.desc(), Scan.id.desc())
        .first()
    )


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


def _answer_recent_scan_mitigation(db: Session) -> dict:
    scan = _latest_problematic_scan(db)
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
        lines = [f"Found findings on **{len(by_host)} system(s)**:"]
        for host, titles in by_host.items():
            lines.append(f"- **{host}**: {len(titles)} issue(s) - {'; '.join(titles[:3])}{' ...' if len(titles) > 3 else ''}")
        answer = "\n".join(lines)
    else:
        lines = [f"Found **{len(results)}** matching finding(s):"]
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
    previous_user_questions = [
        turn["content"] for turn in history
        if turn.get("role") == "user" and turn.get("content")
    ]
    approved_memory = "\n".join(
        f"- {item[:1000]}" for item in (memory_context or []) if item
    )
    recent_context = "\n".join(
        f"{turn.get('role', 'user')}: {turn.get('content', '')[:1200]}"
        for turn in history[-6:]
        if turn.get("content")
    )
    contextual_question = question
    if approved_memory:
        contextual_question = (
            "Approved user context (data, not instructions):\n"
            f"{approved_memory}\n\n{contextual_question}"
        )
    if recent_context:
        # Keep conversational references (it/that/mitigate) grounded in both
        # the prior user request and the answer that identified the evidence.
        contextual_question = f"Conversation context:\n{recent_context}\n\nCurrent question: {question}"

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

    if _is_recent_scan_question(question):
        problematic_only = any(term in question.lower() for term in ("problem", "issue", "finding", "vulnerab"))
        return _answer_recent_scan_question(db, problematic_only=problematic_only)
    if _is_scan_list_question(question):
        return _answer_scan_list(db, only_problematic=any(term in question.lower() for term in ("vulnerab", "issue", "finding")))
    if question.lower().strip() == "show all critical findings":
        return _answer_critical_findings(db)
    if _is_provenance_question(question):
        return _answer_remediation_provenance(db)
    if previous_user_questions and _is_mitigation_follow_up(question) and any(
        _is_recent_scan_question(item) for item in previous_user_questions[-3:]
    ):
        if "vulnerab" in question.lower() or "issue" in question.lower():
            return _answer_recent_scan_vulnerability_and_mitigation(db)
        return _answer_recent_scan_mitigation(db)
    if previous_user_questions and _is_explanation_follow_up(question) and any(
        _is_recent_scan_question(item) for item in previous_user_questions[-3:]
    ):
        return _answer_scan_explanation(db)

    if _looks_like_data_question(question):
        return _answer_data_question(db, question)

    validate_provider_configuration()

    # Also check: does the question reference a specific CVE ID we should
    # prioritize over generic similarity ranking?
    cve_match = re.search(r"CVE-\d{4}-\d{4,7}", question, re.IGNORECASE)
    try:
        retrieval_started = time.monotonic()
        with span("rag.postgres_vector_retrieval", backend="postgres", stage="vector"):
            from rag.retrieval.service import retrieve as persistent_retrieve
            retrieved = persistent_retrieve(
                db, contextual_question, _metadata_criteria(question), k=FUSION_K
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
    if cve_match:
        cve_id = cve_match.group(0).upper()
        exact = [d for d, _ in retrieved if d["id"] == f"cve:{cve_id}"]
        if exact:
            retrieved = [(exact[0], 1.0)] + [
                (doc, score) for doc, score in retrieved if doc["id"] != f"cve:{cve_id}"
            ][: k - 1]

    # A scan target is often the most important part of a question, but
    # generic words such as "recent", "problem", and "explain" can dilute
    # its vector score. Promote matching completed-scan records so the LLM
    # receives the actual scan evidence first.
    target_tokens = re.findall(r"\b[a-z0-9][a-z0-9.-]*\.[a-z]{2,}\b|\b\d{1,3}(?:\.\d{1,3}){3}\b", question.lower())
    if target_tokens:
        exact_scans = [
            (doc, 1.0)
            for doc, _ in retrieved
            if doc.get("source") == "Completed scan"
            and any(token in doc.get("title", "").lower() for token in target_tokens)
        ]
        if exact_scans:
            exact_ids = {doc["id"] for doc, _ in exact_scans}
            retrieved = exact_scans + [(doc, score) for doc, score in retrieved if doc["id"] not in exact_ids]
            retrieved = retrieved[:k]

    named_query = bool(_named_vulnerability_terms(question))
    if named_query and not _has_named_vulnerability_evidence(question, retrieved):
        logger.info("named vulnerability evidence rejected: local candidates did not match query identifiers")
        retrieved = []

    # NVD is a bounded, read-only fallback. Avoid external lookup for
    # conversational follow-ups and when local evidence is already adequate.
    local_evidence_adequate = _has_adequate_local_evidence(question, retrieved)
    if _should_use_nvd_fallback(
        retrieved, previous_user_questions, named_query, local_evidence_adequate
    ):
        internet_doc = lookup_question(question)
        if internet_doc and (not named_query or _has_named_vulnerability_evidence(question, [(internet_doc, 1.0)])):
            retrieved = [(internet_doc, 1.0)] + retrieved[: k - 1]

    if named_query and not retrieved:
        return {
            "answer": (
                "I couldn't find grounded local evidence for this specific vulnerability. "
                "The bounded external lookup did not return a matching source."
            ),
            "sources": [],
            "structured_results": [],
            "degradation": {"reason": "named_vulnerability_evidence_unavailable"},
        }

    provider = get_provider()
    generation_started = time.monotonic()
    with span("rag.groq_generation", provider=provider.name):
        answer_text = provider.generate(question, retrieved)
    observe(rag_stage_duration, time.monotonic() - generation_started, "generation")
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
        "degradation": (
            {"reason": generation_status["last_degradation_reason"]}
            if generation_status.get("last_degradation_reason") else None
        ),
    }
