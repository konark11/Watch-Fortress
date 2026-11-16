from __future__ import annotations
import time
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
import logging

from models.database import (
    AssistantMessage, AssistantRole, RetentionEventType, User, KnowledgeChunk, KnowledgeDoc,
    get_db, now_utc,
)
from assistant.service import (
    _conversation, context_for, create_conversation, create_memory, delete_conversation,
    delete_memory, delete_message, list_conversations, list_memories, next_sequence,
    read_conversation, update_conversation,
)
from jobs.repository import enqueue
from auth.security import get_current_user
from auth.audit import log_action
from api.schemas import AskRequest, ConversationCreate, ConversationUpdate, MemoryCreate
from rag.query_engine import ask, ensure_indexed, index_status, EmbeddingCompatibilityError
from rag.llm_providers import (
    get_provider, RAG_MODE, ProviderError, provider_status,
)
from rag.reranker import status as reranker_status
from rag.settings import (
    DENSE_TOP_K, FINAL_EVIDENCE_K, JEV_MODE, JEV_MODEL, RRF_K, SPARSE_TOP_K,
    EMBEDDING_MODEL, EMBEDDING_REVISION, DEVICE, RERANK_ENABLED,
)
from rag.embeddings import active_embedding_metadata
from security.login_analysis import analyze_login_failures

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/conversations")
def create_assistant_conversation(payload: ConversationCreate, db: Session = Depends(get_db),
                                  user: User = Depends(get_current_user)):
    return create_conversation(db, user, payload.title)


@router.get("/conversations")
def get_assistant_conversations(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return {"conversations": list_conversations(db, user)}


@router.get("/conversations/{conversation_id}")
def get_assistant_conversation(conversation_id: str, offset: int = 0, limit: int = 50,
                               db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return read_conversation(db, conversation_id, user, offset, limit)


@router.patch("/conversations/{conversation_id}")
def patch_assistant_conversation(conversation_id: str, payload: ConversationUpdate,
                                 db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return update_conversation(db, conversation_id, user, payload.title, payload.archived)


@router.delete("/conversations/{conversation_id}")
def remove_assistant_conversation(conversation_id: str, db: Session = Depends(get_db),
                                  user: User = Depends(get_current_user)):
    return delete_conversation(db, conversation_id, user)


@router.delete("/conversations/{conversation_id}/messages/{message_id}")
def remove_assistant_message(conversation_id: str, message_id: str, db: Session = Depends(get_db),
                             user: User = Depends(get_current_user)):
    return delete_message(db, conversation_id, message_id, user)


@router.get("/memories")
def get_assistant_memories(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return {"memories": list_memories(db, user)}


@router.post("/memories")
def add_assistant_memory(payload: MemoryCreate, db: Session = Depends(get_db),
                         user: User = Depends(get_current_user)):
    from models.database import MemoryScope
    return create_memory(
        db, user, content=payload.content, memory_type=payload.memory_type,
        scope=MemoryScope(payload.scope), conversation_id=payload.conversation_id,
        expires_at=payload.expires_at, source_message_id=payload.source_message_id,
    )


@router.delete("/memories/{memory_id}")
def remove_assistant_memory(memory_id: str, db: Session = Depends(get_db),
                            user: User = Depends(get_current_user)):
    return delete_memory(db, memory_id, user)


@router.get("/export")
def export_assistant_data(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    now = now_utc()
    conversations = list_conversations(db, user)
    data = []
    for conversation in conversations:
        data.append(read_conversation(db, conversation["id"], user, 0, 200))
    export = {"exported_at": now, "conversations": data, "memories": list_memories(db, user)}
    log_action(db, user, "assistant.export_requested", "assistant-data", "Conversation and memory export requested")
    from assistant.service import _event
    _event(db, "user", str(user.id), RetentionEventType.EXPORT_REQUESTED, user)
    db.commit()
    return export


@router.post("/ask")
def ask_assistant(payload: AskRequest, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Answer using server history when a conversation id is supplied."""
    started = time.monotonic()
    try:
        if not payload.conversation_id:
            result = ask(db, payload.question, [turn.model_dump() for turn in payload.history])
            return {**result, "reply": result.get("answer", "")}

        conversation = _conversation(db, payload.conversation_id, user)
        history, memories = context_for(db, conversation, user)
        user_message = AssistantMessage(
            conversation_id=conversation.id, sequence=next_sequence(db, conversation),
            role=AssistantRole.USER, content=payload.question, expires_at=conversation.expires_at,
        )
        db.add(user_message)
        db.flush()
        result = ask(db, payload.question, history, memory_context=memories)
        provider_metadata = provider_status()
        assistant_message = AssistantMessage(
            conversation_id=conversation.id, sequence=next_sequence(db, conversation),
            role=AssistantRole.ASSISTANT, content=result.get("answer", ""),
            citations=result.get("sources", []),
            provider=result.get("provider") or get_provider().name,
            model=provider_metadata.get("model"),
            generation_metadata={
                "latency_ms": round((time.monotonic() - started) * 1000, 2),
                "degradation": result.get("degradation"),
                "source_mode": result.get("source_mode", "grounded"),
            },
            expires_at=conversation.expires_at,
        )
        db.add(assistant_message)
        conversation.last_message_at = now_utc()
        conversation.updated_at = now_utc()
        db.commit()
        return {
            **result,
            "reply": result.get("answer", ""),
            "conversation_id": conversation.public_id,
            "message_id": assistant_message.public_id,
            "persisted": True,
        }
    except SQLAlchemyError as exc:
        db.rollback()
        original = getattr(exc, "orig", None)
        logger.error(
            "assistant persistence failed: error_type=%s original_type=%s detail=%s",
            type(exc).__name__,
            type(original).__name__ if original else None,
            str(original or exc)[:500],
        )
        raise HTTPException(status_code=503, detail="Assistant response was not persisted; please retry.") from exc
    except ProviderError as exc:
        db.rollback()
        provider = provider_status()
        # Provider metadata is safe to expose; credentials and payloads are not.
        from observability import safe_log
        safe_log(
            "assistant.generation_failed",
            provider=provider.get("provider"),
            model=provider.get("model"),
            latency_ms=round((time.monotonic() - started) * 1000, 2),
            status=str(exc),
            outcome="provider_error",
        )
        raise HTTPException(
            status_code=503,
            detail="The configured answer service is unavailable. Check assistant provider configuration and try again.",
        ) from exc


@router.post("/chat")
def chat_compat(payload: AskRequest, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return ask_assistant(payload, db, user)


@router.post("/reindex")
def reindex(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    job = enqueue(
        db, job_type="rag.reindex", payload={},
        idempotency_key="rag-reindex:manual:incremental",
        creator_user_id=_.id, creator_username=_.username,
    )
    db.commit()
    return {"ok": True, "job_id": job.public_id, "message": "Incremental RAG indexing queued."}


@router.get("/login-failures")
def login_failure_analysis(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Explain the previous UTC day's failed-login activity from audit data."""
    return analyze_login_failures(db)


@router.get("/status")
def rag_status(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    try:
        embedding_index = index_status(db)
    except (RuntimeError, ValueError, OSError) as exc:
        embedding_index = {
            "state": "unavailable",
            "warning": str(exc),
            "active_embedding": active_embedding_metadata(),
        }
    return {
        "generation": {"mode": RAG_MODE, "name": get_provider().name, **provider_status()},
        "embedding": {
            "model": EMBEDDING_MODEL,
            "revision": EMBEDDING_REVISION or None,
            "device": DEVICE,
            "active": active_embedding_metadata(),
            "index": embedding_index,
        },
        "retrieval": {
            "backend": embedding_index.get("backend"),
            "dense": embedding_index.get("backend") == "postgres",
            "bm25": embedding_index.get("backend") == "sqlite",
            "postgres_full_text": embedding_index.get("backend") == "postgres",
            "rrf": True,
            "dense_top_k": DENSE_TOP_K,
            "sparse_top_k": SPARSE_TOP_K,
            "rrf_k": RRF_K,
            "final_evidence_k": FINAL_EVIDENCE_K,
        },
        "reranker": reranker_status(),
        "reranking_enabled": RERANK_ENABLED,
        "jev": {
            "mode": JEV_MODE,
            "model": JEV_MODEL,
            "status": "unavailable",
            "warning": "No verified JEV adapter or endpoint is configured.",
        },
        "index": {
            "knowledge_documents": db.query(KnowledgeDoc).count(),
            "knowledge_chunks": db.query(KnowledgeChunk).count(),
            "state": embedding_index.get("state"),
            "records": embedding_index.get("document_count", 0),
            "last_job": embedding_index.get("last_job"),
            "last_index_summary": embedding_index.get("last_index_summary"),
            "remediation": embedding_index.get("remediation"),
        },
        "capability": embedding_index.get("capability"),
    }
