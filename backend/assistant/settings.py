from __future__ import annotations

import os


def _int(name: str, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int(os.environ.get(name, str(default))))
    except ValueError:
        return default


CONVERSATION_RETENTION_DAYS = _int("ASSISTANT_CONVERSATION_RETENTION_DAYS", 90)
MESSAGE_RETENTION_DAYS = _int("ASSISTANT_MESSAGE_RETENTION_DAYS", 90)
MEMORY_RETENTION_DAYS = _int("ASSISTANT_MEMORY_RETENTION_DAYS", 90)
CONTEXT_MAX_MESSAGES = _int("ASSISTANT_CONTEXT_MAX_MESSAGES", 12)
CONTEXT_MAX_CHARACTERS = _int("ASSISTANT_CONTEXT_MAX_CHARACTERS", 12000)
MEMORY_MAX_ITEMS = _int("ASSISTANT_MEMORY_MAX_ITEMS", 20)
RETENTION_PURGE_ENABLED = os.environ.get("ASSISTANT_RETENTION_PURGE_ENABLED", "true").lower() in {"1", "true", "yes"}
POLICY_VERSION = "default-v1"

