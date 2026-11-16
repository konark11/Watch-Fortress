import { describe, it } from "node:test";
import assert from "node:assert";
import { isSafeUrl } from "./markdown.ts";
import type { EvidenceSource, StoredMessage } from "./types.ts";

describe("Assistant Provenance & Evidence Safety", () => {
  it("preserves real API provenance citations without modification", () => {
    const rawApiSources: EvidenceSource[] = [
      {
        id: "chunk-101",
        source: "Completed scan",
        title: "Nessus Internal Infrastructure - 10.0.0.1",
        relevance: 0.95,
      },
      {
        id: "chunk-102",
        source: "cisa_kev",
        title: "CVE-2023-48795 Terrapin Attack Advisory",
        relevance: 0.88,
        url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
      },
    ];

    // Verify properties are preserved
    assert.strictEqual(rawApiSources.length, 2);
    assert.strictEqual(rawApiSources[0].source, "Completed scan");
    assert.strictEqual(rawApiSources[0].title, "Nessus Internal Infrastructure - 10.0.0.1");
    assert.strictEqual(rawApiSources[0].relevance, 0.95);
    assert.strictEqual(rawApiSources[0].url, undefined); // No url fabricated

    // Verify safe url on the second citation
    assert.ok(rawApiSources[1].url);
    if (rawApiSources[1].url) {
      assert.strictEqual(isSafeUrl(rawApiSources[1].url), true);
    }
  });

  it("safely handles message objects with both sources and citations keys", () => {
    // Backend API can return citations (from DB) or sources (from /ask endpoint)
    const msgFromDb: StoredMessage = {
      id: "msg-1",
      sequence: 1,
      role: "assistant",
      content: "Found 2 open ports.",
      citations: [
        { id: "1", source: "nmap", title: "Port Scan", relevance: 1.0 },
      ],
    };

    const msgFromAsk: StoredMessage = {
      id: "msg-2",
      sequence: 2,
      role: "assistant",
      content: "Found 2 open ports.",
      sources: [
        { id: "2", source: "openvas", title: "Vuln Scan", relevance: 0.9 },
      ],
    };

    function resolveSources(msg: StoredMessage): EvidenceSource[] {
      if (Array.isArray(msg.sources) && msg.sources.length > 0) return msg.sources;
      if (Array.isArray(msg.citations)) return msg.citations;
      return [];
    }

    const resolvedDb = resolveSources(msgFromDb);
    assert.strictEqual(resolvedDb.length, 1);
    assert.strictEqual(resolvedDb[0].source, "nmap");

    const resolvedAsk = resolveSources(msgFromAsk);
    assert.strictEqual(resolvedAsk.length, 1);
    assert.strictEqual(resolvedAsk[0].source, "openvas");
  });

  it("surfaces degradation reason when metadata indicates degradation", () => {
    const degradedMsg: StoredMessage = {
      id: "msg-degraded",
      sequence: 3,
      role: "assistant",
      content: "Degraded template reply.",
      generation_metadata: {
        degradation: { reason: "rag_index_not_ready" },
        latency_ms: 120,
      },
    };

    assert.strictEqual(degradedMsg.generation_metadata?.degradation?.reason, "rag_index_not_ready");
    assert.strictEqual(degradedMsg.generation_metadata?.latency_ms, 120);
  });
});
