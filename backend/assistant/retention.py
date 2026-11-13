from __future__ import annotations

from sqlalchemy.orm import Session

from assistant.settings import RETENTION_PURGE_ENABLED
from models.database import (
    AssistantConversation, AssistantMemory, AssistantMessage, ConversationStatus,
    RetentionEvent, RetentionEventType, now_utc,
)


def purge_expired(db: Session, batch_size: int = 100) -> dict:
    if not RETENTION_PURGE_ENABLED:
        return {"enabled": False, "conversations": 0, "messages": 0, "memories": 0}
    now = now_utc()
    counts = {"enabled": True, "conversations": 0, "messages": 0, "memories": 0}
    messages = db.query(AssistantMessage).filter(
        AssistantMessage.deleted_at.is_(None), AssistantMessage.expires_at <= now,
    ).order_by(AssistantMessage.id).limit(batch_size).all()
    for message in messages:
        message.deleted_at = now
        counts["messages"] += 1
    memories = db.query(AssistantMemory).filter(
        AssistantMemory.deleted_at.is_(None), AssistantMemory.expires_at <= now,
    ).order_by(AssistantMemory.id).limit(batch_size).all()
    for memory in memories:
        memory.deleted_at = now
        memory.active = False
        counts["memories"] += 1
    conversations = db.query(AssistantConversation).filter(
        AssistantConversation.deleted_at.is_(None), AssistantConversation.expires_at <= now,
        AssistantConversation.status != ConversationStatus.DELETED,
    ).order_by(AssistantConversation.id).limit(batch_size).all()
    for conversation in conversations:
        conversation.deleted_at = now
        conversation.status = ConversationStatus.DELETED
        counts["conversations"] += 1
    db.add(RetentionEvent(
        subject_type="retention", subject_public_id="system",
        event_type=RetentionEventType.PURGE_COMPLETED,
        details=counts,
    ))
    db.commit()
    return counts

