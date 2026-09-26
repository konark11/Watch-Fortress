"""
Pluggable answer-generation backends.

Three interchangeable providers, selected by VULN_RAG_MODE env var:

  "template" (default, always works, zero dependencies, zero network) -
    Deterministically synthesizes an answer from the retrieved documents:
    a direct-answer summary plus the source snippets, so the assistant is
    always useful even with no LLM installed at all. This is what powers
    "air-gapped local RAG mode" out of the box.

  "ollama" - calls a locally-running Ollama server (Llama 3 / Mistral /
    Qwen, etc, whatever the operator has pulled) via its HTTP API. This is
    still fully air-gapped (Ollama runs on localhost, no internet needed
    once the model is pulled) - it's the "better local generation" tier
    above the template fallback.

  "online" - calls any OpenAI-chat-completions-compatible HTTP endpoint
    (configure VULN_ONLINE_LLM_BASE_URL / _API_KEY / _MODEL). This is the
    "online mode" tier for deployments that DO have internet access and
    want a stronger model for explanation quality.

Every provider receives the same (question, retrieved_docs) and returns
plain text - the query engine doesn't need to know which one is active.
"""
from __future__ import annotations
import os
import json
import urllib.request
import urllib.error

RAG_MODE = os.environ.get("VULN_RAG_MODE", "template")

OLLAMA_BASE_URL = os.environ.get("VULN_OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("VULN_OLLAMA_MODEL", "llama3")

ONLINE_BASE_URL = os.environ.get("VULN_ONLINE_LLM_BASE_URL", "")
ONLINE_API_KEY = os.environ.get("VULN_ONLINE_LLM_API_KEY", "")
ONLINE_MODEL = os.environ.get("VULN_ONLINE_LLM_MODEL", "gpt-4o-mini")


def _build_context_block(retrieved_docs: list[dict]) -> str:
    lines = []
    for doc, score in retrieved_docs:
        lines.append(f"[{doc['source']}] {doc['title']}\n{doc['text']}")
    return "\n\n".join(lines)


class TemplateProvider:
    """Zero-dependency, zero-network answer synthesis. Not a real language
    model - a structured summarizer over the retrieved documents. This is
    the safety net that means the assistant NEVER fails to respond, even
    on a machine with no LLM installed at all."""

    name = "template (offline, no LLM)"

    def generate(self, question: str, retrieved_docs: list[dict]) -> str:
        if not retrieved_docs:
            return (
                "I couldn't find anything in the knowledge base or CVE/CWE/CAPEC/ATT&CK/OWASP "
                "reference data that matches this question. A few things that tend to work well:\n\n"
                "- Ask about a specific CVE, e.g. \"How do I fix CVE-2024-3400?\"\n"
                "- Ask about a vulnerability type, e.g. \"Why is SQL injection dangerous?\"\n"
                "- Ask about your scan data, e.g. \"Show all critical findings\"\n\n"
                "Or add relevant material to the Knowledge Base so future queries can retrieve it."
            )

        top_doc, top_score = retrieved_docs[0]
        parts = [f"Based on the {top_doc['source']} entry for **{top_doc['title']}**:\n\n{top_doc['text']}"]

        if len(retrieved_docs) > 1:
            parts.append("\n**Related information:**")
            for doc, score in retrieved_docs[1:]:
                parts.append(f"- [{doc['source']}] {doc['title']}")

        parts.append(
            "\n\n_This answer was assembled by retrieving the most relevant entries from the "
            "local CVE/CWE/CAPEC/ATT&CK/OWASP knowledge base and internal documentation "
            "(offline template mode - no language model is generating this text; configure "
            "VULN_RAG_MODE=ollama for natural-language synthesis via a local LLM)._"
        )
        return "\n".join(parts)


class OllamaProvider:
    """Calls a local Ollama server for natural-language synthesis over the
    retrieved context. Genuinely untestable in this sandbox (no Ollama
    binary/model available here) - shaped exactly to Ollama's documented
    /api/generate endpoint, so pointing VULN_OLLAMA_BASE_URL at a real
    local Ollama instance with a pulled model works as written."""

    name = f"ollama ({OLLAMA_MODEL})"

    def generate(self, question: str, retrieved_docs: list[dict]) -> str:
        context = _build_context_block(retrieved_docs)
        prompt = (
            "You are a security analyst assistant. Answer the question using ONLY the "
            "context below. If the context doesn't contain the answer, say so plainly.\n\n"
            f"Context:\n{context}\n\nQuestion: {question}\n\nAnswer:"
        )
        body = json.dumps({"model": OLLAMA_MODEL, "prompt": prompt, "stream": False}).encode()
        req = urllib.request.Request(
            f"{OLLAMA_BASE_URL}/api/generate", data=body,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read())
                return data.get("response", "").strip() or "(empty response from Ollama)"
        except (urllib.error.URLError, OSError) as e:
            return (
                f"Could not reach Ollama at {OLLAMA_BASE_URL} ({e}). "
                "Falling back to offline template mode is recommended (VULN_RAG_MODE=template) "
                "if Ollama is not running on this deployment.\n\n" + TemplateProvider().generate(question, retrieved_docs)
            )


class OnlineProvider:
    """Calls any OpenAI-chat-completions-compatible HTTP endpoint. Generic
    on purpose - deployments can point this at whichever online model
    provider their organization has approved for non-air-gapped use."""

    name = f"online ({ONLINE_MODEL})"

    def generate(self, question: str, retrieved_docs: list[dict]) -> str:
        if not (ONLINE_BASE_URL and ONLINE_API_KEY):
            return (
                "Online mode is not configured (set VULN_ONLINE_LLM_BASE_URL and "
                "VULN_ONLINE_LLM_API_KEY). Falling back to offline template mode:\n\n"
                + TemplateProvider().generate(question, retrieved_docs)
            )
        context = _build_context_block(retrieved_docs)
        body = json.dumps({
            "model": ONLINE_MODEL,
            "messages": [
                {"role": "system", "content": "You are a security analyst assistant. Answer using only the provided context."},
                {"role": "user", "content": f"Context:\n{context}\n\nQuestion: {question}"},
            ],
        }).encode()
        req = urllib.request.Request(
            f"{ONLINE_BASE_URL}/chat/completions", data=body,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {ONLINE_API_KEY}"}, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read())
                return data["choices"][0]["message"]["content"].strip()
        except (urllib.error.URLError, OSError, KeyError, IndexError) as e:
            return f"Online LLM call failed ({e}). Falling back to offline template mode:\n\n" + TemplateProvider().generate(question, retrieved_docs)


def get_provider():
    if RAG_MODE == "ollama":
        return OllamaProvider()
    if RAG_MODE == "online":
        return OnlineProvider()
    return TemplateProvider()
