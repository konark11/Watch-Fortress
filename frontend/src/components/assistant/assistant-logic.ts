import type { StoredMessage } from "./types";

/**
 * Validates whether a message can be submitted.
 */
export function canSubmitMessage(text: string, busy: boolean): boolean {
  return !busy && text.trim().length > 0;
}

/**
 * Prepares the payload for sending a question.
 */
export function sanitizeQuestionInput(text: string): string {
  return text.trim();
}

/**
 * Determines appropriate user-facing error message from caught exception.
 */
export function formatAssistantError(err: unknown, isAborted = false): string {
  if (isAborted || (err instanceof DOMException && err.name === "AbortError")) {
    return "Request was cancelled. Check the backend RAG status and try again.";
  }
  if (err instanceof Error) {
    return err.message;
  }
  return "Assistant request failed.";
}

/**
 * Checks whether an element is scrolled near the bottom (within threshold px).
 */
export function isScrolledNearBottom(
  scrollHeight: number,
  scrollTop: number,
  clientHeight: number,
  threshold = 100
): boolean {
  return scrollHeight - scrollTop - clientHeight <= threshold;
}

/**
 * Creates a synthetic local message for immediate optimistic or error display.
 */
export function createLocalMessage(
  role: "user" | "assistant",
  content: string,
  error = false
): StoredMessage {
  return {
    id: `local-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    sequence: 999999,
    role,
    content,
    error,
    created_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 86400000 * 30).toISOString(),
    sources: [],
    citations: [],
  };
}
