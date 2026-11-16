from __future__ import annotations

import json
import urllib.error

def test_nvd_lookup_uses_short_configurable_timeout(monkeypatch):
    import rag.internet_lookup as lookup

    calls = []
    monkeypatch.setenv("RAG_NVD_LOOKUP_TIMEOUT_SECONDS", "3")
    monkeypatch.setattr(lookup, "NVD_API_KEY", "test-key")

    def timeout(request, timeout):
        calls.append(timeout)
        assert request.get_header("Apikey") == "test-key"
        assert request.get_header("User-agent") == "Watch-Fortress/1.0"
        raise TimeoutError

    monkeypatch.setattr(lookup.urllib.request, "urlopen", timeout)
    assert lookup.lookup_question("OpenSSH Terrapin") is None
    assert calls == [3]


def test_nvd_lookup_handles_http_errors_without_exposing_credentials(monkeypatch, caplog):
    import rag.internet_lookup as lookup

    monkeypatch.setattr(lookup, "NVD_API_KEY", "test-key")

    def reject(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 403, "forbidden", {}, None)

    monkeypatch.setattr(lookup.urllib.request, "urlopen", reject)
    assert lookup.lookup_question("CVE-2023-1298") is None
    assert "status=403" in caplog.text
    assert "test-key" not in caplog.text


def test_nvd_lookup_parses_successful_cve_response(monkeypatch):
    import rag.internet_lookup as lookup

    monkeypatch.setattr(lookup, "NVD_API_KEY", "test-key")

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self):
            return json.dumps({
                "vulnerabilities": [{
                    "cve": {
                        "id": "CVE-2023-1298",
                        "descriptions": [{"lang": "en", "value": "Example vulnerability."}],
                        "metrics": {"cvssMetricV31": [{
                            "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"},
                        }]},
                    },
                }],
            }).encode()

    def succeed(request, timeout):
        assert request.get_header("Apikey") == "test-key"
        assert request.get_header("User-agent") == "Watch-Fortress/1.0"
        assert "cveId=CVE-2023-1298" in request.full_url
        return Response()

    monkeypatch.setattr(lookup.urllib.request, "urlopen", succeed)
    result = lookup.lookup_question("CVE-2023-1298")
    assert result["id"] == "nvd:CVE-2023-1298"
    assert result["title"] == "CVE-2023-1298"
    assert "CVSS v3 score: 7.5" in result["text"]


def test_nvd_fallback_skips_conversational_followups():
    from rag.query_engine import _has_adequate_local_evidence, _should_use_nvd_fallback

    assert not _should_use_nvd_fallback([], ["What did the latest scan find?"])
    assert not _should_use_nvd_fallback([({"id": "cve:X"}, 0.5)], [])
    assert not _should_use_nvd_fallback([({"id": "cve:terrapin"}, 0.02)], [], True)
    local = [({"title": "SQL Injection", "text": "SQL injection remediation"}, 0.02)]
    assert _has_adequate_local_evidence("Why is SQL injection dangerous?", local)
    assert not _should_use_nvd_fallback(local, [], False, True)
    assert not _should_use_nvd_fallback([], [])


def test_named_vulnerability_rejects_unrelated_evidence():
    from rag.query_engine import _has_named_vulnerability_evidence

    unrelated = [({
        "title": "CAPEC-489 - SSL Flood",
        "text": "A denial of service technique.",
    }, 0.9)]
    relevant = [({
        "title": "CVE-2023-48795 - Terrapin",
        "text": "The OpenSSH Terrapin attack truncates the SSH prefix.",
    }, 0.2)]

    assert not _has_named_vulnerability_evidence("OpenSSH Terrapin attack", unrelated)
    assert _has_named_vulnerability_evidence("OpenSSH Terrapin attack", relevant)


def test_general_questions_are_not_confused_with_named_vulnerabilities():
    from rag.query_engine import _has_adequate_local_evidence, _is_general_question

    assert _is_general_question("What does CVSS base score mean?")
    assert _is_general_question("How does least privilege work?")
    assert not _is_general_question("What is the CVSS score of CVE-2026-34197?")
    assert not _has_adequate_local_evidence(
        "What does CVSS base score mean?",
        [({"title": "CVE-2026-34197", "text": "ActiveMQ code injection"}, 0.9)],
    )


def test_explicit_cve_context_is_scoped_before_generation():
    from rag.query_engine import _scope_retrieved_evidence

    retrieved = [
        ({"id": "cve:CVE-2026-34197", "title": "CVE-2026-34197", "text": "ActiveMQ"}, 0.9),
        ({"id": "cve:CVE-2023-46604", "title": "CVE-2023-46604", "text": "ActiveMQ"}, 0.8),
    ]
    scoped, target = _scope_retrieved_evidence(
        "Give remediation for CVE-2026-34197 only", retrieved
    )

    assert target == "CVE-2026-34197"
    assert [doc["id"] for doc, _ in scoped] == ["cve:CVE-2026-34197"]


def test_unicode_dash_normalization():
    from rag.relevance import normalize_security_query

    # Unicode non-breaking hyphen \u2011, en-dash \u2013, em-dash \u2014, minus \u2212, small hyphen \ufe63, fullwidth \uff0d, soft hyphen \u00ad
    sample = "what is CVE\u20112023\u201120198?"
    normalized = normalize_security_query(sample)
    assert normalized == "what is CVE-2023-20198?"

    dashes = ["\u2010", "\u2011", "\u2012", "\u2013", "\u2014", "\u2212", "\ufe63", "\uff0d"]
    for d in dashes:
        assert normalize_security_query(f"CVE{d}2024{d}3400") == "CVE-2024-3400"


def test_resolve_focal_context_direct_cve():
    from rag.query_engine import resolve_focal_context

    q, cve = resolve_focal_context("what is CVE\u20112023\u201120198?")
    assert cve == "CVE-2023-20198"
    assert "CVE-2023-20198" in q


def test_resolve_focal_context_multi_turn_anaphora_and_attributes():
    from rag.query_engine import resolve_focal_context

    history = [
        {"role": "user", "content": "what is CVE\u20112023\u201120198?"},
        {"role": "assistant", "content": "CVE-2023-20198 is a Cisco IOS XE Web UI vulnerability."},
    ]

    # Follow up with "this"
    q, cve = resolve_focal_context("what is the CVSS score of this?", history)
    assert cve == "CVE-2023-20198"
    assert "(referring to CVE-2023-20198)" in q

    # Follow up with "it"
    q2, cve2 = resolve_focal_context("how do I fix it?", history)
    assert cve2 == "CVE-2023-20198"

    # Follow up with "the vulnerability"
    q3, cve3 = resolve_focal_context("is the vulnerability exploited in the wild?", history)
    assert cve3 == "CVE-2023-20198"


def test_resolve_focal_context_switches_on_new_target():
    from rag.query_engine import resolve_focal_context

    history = [
        {"role": "user", "content": "what is CVE-2023-20198?"},
        {"role": "assistant", "content": "Cisco IOS XE Web UI vulnerability."},
    ]
    # New question explicitly mentions another CVE
    q, cve = resolve_focal_context("what about CVE-2024-3400?", history)
    assert cve == "CVE-2024-3400"


def test_general_question_guard_with_active_cve():
    from rag.query_engine import _is_general_question

    # Without active_cve, "what is..." is general
    assert _is_general_question("what is the CVSS score of this?") is True

    # With active_cve, follow-up is NOT general, preserving grounded RAG retrieval
    assert _is_general_question("what is the CVSS score of this?", active_cve="CVE-2023-20198") is False
    assert _is_general_question("what is its severity?", active_cve="CVE-2023-20198") is False

    # Standalone conceptual question remains general
    assert _is_general_question("what is cross-site scripting?") is True


def test_scope_retrieved_evidence_with_active_cve():
    from rag.query_engine import _scope_retrieved_evidence

    retrieved = [
        ({"id": "cve:CVE-2023-20198", "title": "CVE-2023-20198", "text": "Cisco IOS XE"}, 1.0),
        ({"id": "cve:CVE-2023-20273", "title": "CVE-2023-20273", "text": "Cisco IOS XE injection"}, 0.8),
        ({"id": "cve:CVE-2024-3400", "title": "CVE-2024-3400", "text": "Palo Alto PAN-OS"}, 0.5),
    ]
    scoped, target = _scope_retrieved_evidence("what is the CVSS score of this?", retrieved, active_cve="CVE-2023-20198")
    assert target == "CVE-2023-20198"
    assert len(scoped) == 1
    assert scoped[0][0]["id"] == "cve:CVE-2023-20198"


def test_multi_turn_cve_ask_end_to_end(monkeypatch):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from models.database import Base
    import rag.query_engine as qe

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()

    class MockProvider:
        name = "mock"
        def __init__(self):
            self.last_prompt = None
            self.last_evidence = None
            self.general_calls = 0
            self.generate_calls = 0
        def generate(self, prompt, evidence, history=None):
            self.generate_calls += 1
            self.last_prompt = prompt
            self.last_evidence = evidence
            self.last_history = history
            return "The CVSS v3 score for CVE-2023-20198 is 10.0 (CRITICAL)."
        def generate_general(self, prompt, history=None):
            self.general_calls += 1
            return "General response without evidence."

    mock_p = MockProvider()
    monkeypatch.setattr(qe, "get_provider", lambda: mock_p)
    monkeypatch.setattr(qe, "_indexed", True)
    monkeypatch.setattr(qe, "ensure_indexed", lambda db: None)
    monkeypatch.setattr(qe, "validate_provider_configuration", lambda: None)
    monkeypatch.setattr(qe, "RERANK_ENABLED", False)
    import rag.retrieval.service as ret_service
    monkeypatch.setattr(ret_service, "retrieve", lambda db, q, criteria=None, k=20: [])

    # Turn 1: user asks about CVE-2023-20198 (with Unicode non-breaking dash)
    res1 = qe.ask(session, "what is CVE\u20112023\u201120198?")
    assert res1["source_mode"] == "grounded"
    assert any("CVE-2023-20198" in s["id"] for s in res1["sources"])
    assert mock_p.generate_calls == 1

    # Turn 2: user asks "what is the CVSS score of this?" with Turn 1 in history
    history = [
        {"role": "user", "content": "what is CVE\u20112023\u201120198?"},
        {"role": "assistant", "content": res1["answer"]},
    ]
    res2 = qe.ask(session, "what is the CVSS score of this?", history=history)
    assert res2["source_mode"] == "grounded"
    assert any("CVE-2023-20198" in s["id"] for s in res2["sources"])
    assert "CVE-2023-20198" in mock_p.last_prompt
    assert mock_p.general_calls == 0


def test_scan_priority_follow_up_detection():
    from rag.query_engine import _is_scan_priority_follow_up

    assert _is_scan_priority_follow_up("what is the most important finding i should care about?")
    assert _is_scan_priority_follow_up("what is the most important finding i should care about in the scan?")
    assert _is_scan_priority_follow_up("what is the most important finding i should care about in the scan above in the chat?")
    assert _is_scan_priority_follow_up("which finding is most critical?")
    assert _is_scan_priority_follow_up("what should i prioritize first?")
    assert _is_scan_priority_follow_up("what is the highest priority finding?")
    assert not _is_scan_priority_follow_up("hello there")


def test_answer_recent_scan_priorities_flow(monkeypatch):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from models.database import Base, Scan, Finding, ScanStatus, Severity, ScannerType
    import rag.query_engine as qe
    from datetime import datetime, timezone

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()

    scan = Scan(
        name="Internal Network Baseline",
        scanner_type=ScannerType.NUCLEI,
        target="scanme.nmap.org",
        status=ScanStatus.COMPLETED,
        findings_count=2,
        finished_at=datetime.now(timezone.utc),
    )
    session.add(scan)
    session.commit()

    f1 = Finding(
        scan_id=scan.id,
        title="Apache mod_negotiation - Pseudo Directory Listing",
        severity=Severity.LOW,
        asset_ip="45.33.32.156",
        port_number=None,
        cve_ids=[],
        description="Directory listing enabled.",
        solution="Disable mod_negotiation or MultiViews.",
    )
    f2 = Finding(
        scan_id=scan.id,
        title="OpenSSH Terrapin Attack - Detection",
        severity=Severity.MEDIUM,
        asset_ip="45.33.32.156",
        port_number=22,
        cve_ids=["CVE-2023-48795"],
        description="OpenSSH prefix truncation vulnerability.",
        solution="Update OpenSSH to 9.6 or later.",
    )
    session.add_all([f1, f2])
    session.commit()

    monkeypatch.setattr(qe, "_indexed", True)
    monkeypatch.setattr(qe, "ensure_indexed", lambda db: None)
    monkeypatch.setattr(qe, "validate_provider_configuration", lambda: None)

    # Turn 1: user asks for latest scan findings
    res1 = qe.ask(session, "What are the latest scan findings and remediation priorities?")
    assert "Internal Network Baseline" in res1["answer"]
    assert "OpenSSH Terrapin Attack" in res1["answer"]

    # Turn 2: user asks "what is the most important finding i should care about?"
    history = [
        {"role": "user", "content": "What are the latest scan findings and remediation priorities?"},
        {"role": "assistant", "content": res1["answer"]},
    ]
    res2 = qe.ask(session, "what is the most important finding i should care about?", history=history)
    assert "OpenSSH Terrapin Attack" in res2["answer"]
    assert "CVE-2023-48795" in res2["answer"]
    assert "45.33.32.156:22" in res2["answer"]
    assert res2["sources"][0]["source"] == "Completed scan"

    # Turn 3: user asks "what is the most important finding i should care about in the scan?"
    res3 = qe.ask(session, "what is the most important finding i should care about in the scan?", history=history)
    assert "OpenSSH Terrapin Attack" in res3["answer"]

    # Turn 4: user asks "what is the most important finding i should care about in the scan above in the chat?"
    res4 = qe.ask(session, "what is the most important finding i should care about in the scan above in the chat?", history=history)
    assert "OpenSSH Terrapin Attack" in res4["answer"]


