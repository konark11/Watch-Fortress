export interface KeyDownDecision {
  shouldSubmit: boolean;
  shouldPreventDefault: boolean;
  insertNewline: boolean;
}

/**
 * Pure decision function for keyboard events in the composer.
 */
export function evaluateComposerKeydown(
  key: string,
  shiftKey: boolean,
  busy: boolean,
  text: string
): KeyDownDecision {
  const hasText = text.trim().length > 0;

  if (key === "Enter") {
    if (shiftKey) {
      // Shift+Enter allows newline insertion without submitting
      return {
        shouldSubmit: false,
        shouldPreventDefault: false,
        insertNewline: true,
      };
    }
    // Enter alone: prevents default newline, submits only if hasText and not busy
    return {
      shouldSubmit: !busy && hasText,
      shouldPreventDefault: true,
      insertNewline: false,
    };
  }

  return {
    shouldSubmit: false,
    shouldPreventDefault: false,
    insertNewline: false,
  };
}
