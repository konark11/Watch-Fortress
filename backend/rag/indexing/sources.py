from __future__ import annotations

import hashlib
import json
from typing import Any


def source_parts(document: dict[str, Any]) -> tuple[str, str, int]:
    """Return stable source identity without depending on display labels."""
    identifier = str(document["id"])
    source_type, _, source_id = identifier.partition(":")
    chunk_index = int(document.get("metadata", {}).get("chunk_index", 0) or 0)
    if identifier.startswith("kb-chunk:"):
        source_type, source_id = "knowledge_chunk", source_id
    return source_type[:80], source_id[:255], chunk_index


def content_hash(document: dict[str, Any]) -> str:
    metadata = document.get("metadata") or {}
    stable_metadata = {
        key: metadata[key] for key in sorted(metadata)
        if key not in {"embedding", "indexed", "created_at"}
    }
    payload = {
        "title": " ".join(str(document.get("title", "")).split()),
        "text": " ".join(str(document.get("text", "")).split()),
        "metadata": stable_metadata,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def scope_matches(document: dict[str, Any], scope: dict[str, Any] | None) -> bool:
    if not scope:
        return True
    source_type, source_id, _ = source_parts(document)
    requested_type = str(scope.get("source_type") or "").strip()
    document_id = str(scope.get("document_id") or "").strip()
    requested_id = str(scope.get("source_id") or scope.get("scan_id") or "").strip()
    if requested_type and source_type != requested_type:
        return False
    if document_id and str((document.get("metadata") or {}).get("document_id")) != document_id:
        return False
    requested_scan = str(scope.get("scan_id") or "").strip()
    if requested_scan and str((document.get("metadata") or {}).get("scan_id", source_id)) != requested_scan:
        return False
    if requested_id and source_id != requested_id:
        return False
    return bool(requested_type or requested_id or document_id)
