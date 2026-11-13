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
    assert _should_use_nvd_fallback([], [])


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
