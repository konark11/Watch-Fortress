import { describe, it } from "node:test";
import assert from "node:assert";
import {
  canSubmitMessage,
  sanitizeQuestionInput,
  formatAssistantError,
  isScrolledNearBottom,
  createLocalMessage,
} from "./assistant-logic.ts";

describe("Assistant Logic & Validation", () => {
  it("prevents submitting empty or whitespace-only messages", () => {
    assert.strictEqual(canSubmitMessage("", false), false);
    assert.strictEqual(canSubmitMessage("   ", false), false);
    assert.strictEqual(canSubmitMessage("\n\t\n", false), false);
  });

  it("prevents submitting when busy even if text is present (duplicate prevention)", () => {
    assert.strictEqual(canSubmitMessage("How to patch OpenSSH?", true), false);
    assert.strictEqual(canSubmitMessage("", true), false);
  });

  it("allows submitting valid non-whitespace text when idle", () => {
    assert.strictEqual(canSubmitMessage("What are recent scan findings?", false), true);
    assert.strictEqual(canSubmitMessage("  CVE-2023-48795  ", false), true);
  });

  it("trims whitespace from question input", () => {
    assert.strictEqual(
      sanitizeQuestionInput("   Explain CVE-2023-48795   \n"),
      "Explain CVE-2023-48795"
    );
  });

  it("formats cancellation and abort errors accurately", () => {
    const abortErr = new DOMException("The user aborted a request.", "AbortError");
    assert.strictEqual(
      formatAssistantError(abortErr),
      "Request was cancelled. Check the backend RAG status and try again."
    );

    const normalErr = new Error("Database timeout");
    assert.strictEqual(formatAssistantError(normalErr), "Database timeout");

    assert.strictEqual(formatAssistantError("unknown failure"), "Assistant request failed.");
  });

  it("detects whether scroll position is near bottom", () => {
    // scrollHeight=1000, scrollTop=750, clientHeight=200 -> distance=50 <= 100 -> true
    assert.strictEqual(isScrolledNearBottom(1000, 750, 200, 100), true);

    // scrollHeight=1000, scrollTop=500, clientHeight=200 -> distance=300 > 100 -> false
    assert.strictEqual(isScrolledNearBottom(1000, 500, 200, 100), false);
  });

  it("creates a properly formed local message object", () => {
    const msg = createLocalMessage("user", "Explain Terrapin");
    assert.strictEqual(msg.role, "user");
    assert.strictEqual(msg.content, "Explain Terrapin");
    assert.strictEqual(msg.error, false);
    assert.ok(msg.id.startsWith("local-"));
    assert.ok(Array.isArray(msg.sources));
  });

  it("creates an error message with error flag set", () => {
    const msg = createLocalMessage("assistant", "Request timed out", true);
    assert.strictEqual(msg.role, "assistant");
    assert.strictEqual(msg.error, true);
    assert.strictEqual(msg.content, "Request timed out");
  });
});
