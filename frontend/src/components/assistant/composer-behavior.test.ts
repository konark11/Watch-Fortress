import { describe, it } from "node:test";
import assert from "node:assert";
import { evaluateComposerKeydown } from "./composer-behavior.ts";

describe("Composer Keyboard & Submission Behavior", () => {
  it("submits on Enter (without Shift) when text is present and not busy", () => {
    const decision = evaluateComposerKeydown("Enter", false, false, "What is CVE-2023-48795?");
    assert.strictEqual(decision.shouldSubmit, true);
    assert.strictEqual(decision.shouldPreventDefault, true);
    assert.strictEqual(decision.insertNewline, false);
  });

  it("does not submit on Shift+Enter and permits newline insertion", () => {
    const decision = evaluateComposerKeydown("Enter", true, false, "Line 1");
    assert.strictEqual(decision.shouldSubmit, false);
    assert.strictEqual(decision.shouldPreventDefault, false);
    assert.strictEqual(decision.insertNewline, true);
  });

  it("does not submit on Enter when text is empty or whitespace-only", () => {
    const emptyDecision = evaluateComposerKeydown("Enter", false, false, "");
    assert.strictEqual(emptyDecision.shouldSubmit, false);
    assert.strictEqual(emptyDecision.shouldPreventDefault, true);

    const whitespaceDecision = evaluateComposerKeydown("Enter", false, false, "   \n  ");
    assert.strictEqual(whitespaceDecision.shouldSubmit, false);
    assert.strictEqual(whitespaceDecision.shouldPreventDefault, true);
  });

  it("does not submit on Enter when request is already in-flight (busy)", () => {
    const decision = evaluateComposerKeydown("Enter", false, true, "Valid query");
    assert.strictEqual(decision.shouldSubmit, false);
    assert.strictEqual(decision.shouldPreventDefault, true);
  });

  it("ignores non-Enter keystrokes", () => {
    const decision = evaluateComposerKeydown("a", false, false, "hello");
    assert.strictEqual(decision.shouldSubmit, false);
    assert.strictEqual(decision.shouldPreventDefault, false);
    assert.strictEqual(decision.insertNewline, false);
  });
});
