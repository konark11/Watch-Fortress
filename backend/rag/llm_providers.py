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
OPENROUTER_BASE_URL = os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL = os.environ.get("OPENROUTER_MODEL", "poolside/laguna-s-2.1:free")

PLAIN_LANGUAGE_SYSTEM_PROMPT = """You are Watch Fortress, a security assistant.
Answer the user's question using only the supplied information.

Write for a non-technical reader by default:
- Start with the direct answer.
- Use short sentences and familiar words.
- Use bullets when they make the answer easier to scan.
- Explain a technical term in plain words the first time it is needed.
- Do not explain what the knowledge base, evidence, retrieval, model, prompt, or RAG is.
- Do not mention how the answer was generated.
- Do not repeat the question or add a generic disclaimer.
- If the information is not enough, say "I don't have enough information to answer that yet" and say what would help.
- Only use deep technical detail when the user clearly asks for it or is asking another security tool or agent.

Keep the answer focused and useful. Do not invent facts or recommendations."""


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
                "I couldn't find enough information to answer that yet. Try one of these:\n\n"
                "- Ask about a specific CVE, e.g. \"How do I fix CVE-2024-3400?\"\n"
                "- Ask about a vulnerability type, e.g. \"Why is SQL injection dangerous?\"\n"
                "- Ask about your scan data, e.g. \"Show all critical findings\""
            )

        top_doc, top_score = retrieved_docs[0]
        text = " ".join(top_doc["text"].split())
        if len(text) > 700:
            text = text[:697].rsplit(" ", 1)[0] + "..."
        parts = [f"### {top_doc['title']}\n\n{text}"]

        if len(retrieved_docs) > 1:
            parts.append("\n**Related topics:**")
            for doc, score in retrieved_docs[1:]:
                parts.append(f"- {doc['title']}")

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
            f"{PLAIN_LANGUAGE_SYSTEM_PROMPT}\n\n"
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
                return data.get("response", "").strip() or "I couldn't generate an answer right now."
        except (urllib.error.URLError, OSError):
            return (
                "I couldn't reach the answer service, so here's the information I found:\n\n"
                + TemplateProvider().generate(question, retrieved_docs)
            )


class OnlineProvider:
    """Calls any OpenAI-chat-completions-compatible HTTP endpoint. Generic
    on purpose - deployments can point this at whichever online model
    provider their organization has approved for non-air-gapped use."""

    name = f"online ({ONLINE_MODEL})"

    def generate(self, question: str, retrieved_docs: list[dict]) -> str:
        if not (ONLINE_BASE_URL and ONLINE_API_KEY):
            return (
                "The online answer service is not available, so here's the information I found:\n\n"
                + TemplateProvider().generate(question, retrieved_docs)
            )
        context = _build_context_block(retrieved_docs)
        body = json.dumps({
            "model": ONLINE_MODEL,
            "messages": [
                {"role": "system", "content": PLAIN_LANGUAGE_SYSTEM_PROMPT},
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
        except (urllib.error.URLError, OSError, KeyError, IndexError):
            return "I couldn't reach the answer service, so here's the information I found:\n\n" + TemplateProvider().generate(question, retrieved_docs)


class OpenRouterProvider:
    name = f"openrouter ({OPENROUTER_MODEL})"

    def generate(self, question: str, retrieved_docs: list[dict]) -> str:
        if not OPENROUTER_API_KEY:
            return "The answer service is not available, so here's the information I found:\n\n" + TemplateProvider().generate(question, retrieved_docs)
        context = _build_context_block(retrieved_docs)
        body = json.dumps({"model": OPENROUTER_MODEL, "messages": [
            {"role": "system", "content": PLAIN_LANGUAGE_SYSTEM_PROMPT},
            {"role": "user", "content": f"Evidence:\n{context}\n\nQuestion: {question}"},
        ], "temperature": 0.1, "max_tokens": 800}).encode()
        req = urllib.request.Request(
            f"{OPENROUTER_BASE_URL.rstrip('/')}/chat/completions", data=body,
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + OPENROUTER_API_KEY},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read())["choices"][0]["message"]["content"].strip()
        except (urllib.error.HTTPError, urllib.error.URLError, OSError, KeyError, IndexError, ValueError):
            return "I couldn't reach the answer service, so here's the information I found:\n\n" + TemplateProvider().generate(question, retrieved_docs)


def get_provider():
    if RAG_MODE == "ollama":
        return OllamaProvider()
    if RAG_MODE == "online":
        return OnlineProvider()
    if RAG_MODE == "openrouter":
        return OpenRouterProvider()
    return TemplateProvider()
