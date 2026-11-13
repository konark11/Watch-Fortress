from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from assistant.settings import (
    CONTEXT_MAX_CHARACTERS, CONTEXT_MAX_MESSAGES, MEMORY_MAX_ITEMS,
    MEMORY_RETENTION_DAYS, MESSAGE_RETENTION_DAYS, POLICY_VERSION,
)
from auth.audit import log_action
from models.database import (
    AssistantConversation, AssistantMemory, AssistantMessage, AssistantRole,
    ConversationStatus, MemoryCreationMethod, MemoryScope, RetentionEvent,
    RetentionEventType, User, now_utc,
)


def _expiry(days: int) -> datetime:
    return now_utc() + timedelta(days=days)


def _conversation(db: Session, public_id: str, user: User) -> AssistantConversation:
    conversation = (
        db.query(AssistantConversation)
        .filter(AssistantConversation.public_id == public_id, AssistantConversation.owner_user_id == user.id)
        .with_for_update()
        .first()
    )
    if not conversation or conversation.deleted_at or conversation.status == ConversationStatus.DELETED:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
    return conversation


def _event(db: Session, subject_type: str, subject_id: str, event_type: RetentionEventType,
           actor: User | None, details: dict | None = None) -> None:
    db.add(RetentionEvent(
        subject_type=subject_type, subject_public_id=subject_id, event_type=event_type,
        actor_user_id=actor.id if actor else None, details=details or {},
    ))


def conversation_summary(conversation: AssistantConversation) -> dict:
    return {
        "id": conversation.public_id, "title": conversation.title,
        "status": conversation.status.value, "created_at": conversation.created_at,
        "updated_at": conversation.updated_at, "last_message_at": conversation.last_message_at,
        "expires_at": conversation.expires_at,
    }


def create_conversation(db: Session, user: User, title: str | None = None) -> dict:
    conversation = AssistantConversation(
        owner_user_id=user.id, title=(title or "New conversation").strip()[:255] or "New conversation",
        retention_policy_version=POLICY_VERSION, expires_at=_expiry(MESSAGE_RETENTION_DAYS),
    )
    db.add(conversation)
    db.flush()
    _event(db, "conversation", conversation.public_id, RetentionEventType.POLICY_SET, user,
           {"policy_version": POLICY_VERSION, "retention_days": MESSAGE_RETENTION_DAYS})
    db.commit()
    return conversation_summary(conversation)


def list_conversations(db: Session, user: User) -> list[dict]:
    now = now_utc()
    rows = (
        db.query(AssistantConversation)
        .filter(
            AssistantConversation.owner_user_id == user.id,
            AssistantConversation.status != ConversationStatus.DELETED,
            AssistantConversation.deleted_at.is_(None),
            AssistantConversation.expires_at > now,
        )
        .order_by(AssistantConversation.updated_at.desc(), AssistantConversation.id.desc())
        .all()
    )
    return [conversation_summary(row) for row in rows]


def read_conversation(db: Session, public_id: str, user: User, offset: int = 0, limit: int = 50) -> dict:
    conversation = _conversation(db, public_id, user)
    now = now_utc()
    messages = (
        db.query(AssistantMessage)
        .filter(
            AssistantMessage.conversation_id == conversation.id,
            AssistantMessage.deleted_at.is_(None),
            AssistantMessage.expires_at > now,
        )
        .order_by(AssistantMessage.sequence)
        .offset(max(0, offset)).limit(min(max(1, limit), 200)).all()
    )
    return {
        **conversation_summary(conversation),
        "messages": [
            {
                "id": message.public_id, "sequence": message.sequence, "role": message.role.value,
                "content": message.content, "citations": message.citations or [],
                "provider": message.provider, "model": message.model,
                "generation_metadata": message.generation_metadata or [],
                "created_at": message.created_at, "expires_at": message.expires_at,
            } for message in messages
        ],
    }


def update_conversation(db: Session, public_id: str, user: User, title: str | None = None,
                        archived: bool | None = None) -> dict:
    conversation = _conversation(db, public_id, user)
    if title is not None:
        conversation.title = title.strip()[:255] or "Untitled conversation"
    if archived is not None:
        conversation.status = ConversationStatus.ARCHIVED if archived else ConversationStatus.ACTIVE
    conversation.updated_at = now_utc()
    db.commit()
    return conversation_summary(conversation)


def delete_conversation(db: Session, public_id: str, user: User) -> dict:
    conversation = _conversation(db, public_id, user)
    conversation.status = ConversationStatus.DELETED
    conversation.deleted_at = now_utc()
    conversation.updated_at = now_utc()
    _event(db, "conversation", conversation.public_id, RetentionEventType.CONVERSATION_DELETED, user)
    log_action(db, user, "assistant.conversation_deleted", f"conversation:{conversation.public_id}",
               "Conversation soft-deleted")
    db.commit()
    return {"ok": True}


def delete_message(db: Session, conversation_id: str, message_id: str, user: User) -> dict:
    conversation = _conversation(db, conversation_id, user)
    message = (
        db.query(AssistantMessage)
        .filter(AssistantMessage.public_id == message_id, AssistantMessage.conversation_id == conversation.id,
                AssistantMessage.deleted_at.is_(None)).first()
    )
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    message.deleted_at = now_utc()
    _event(db, "message", message.public_id, RetentionEventType.MESSAGE_DELETED, user)
    log_action(db, user, "assistant.message_deleted", f"message:{message.public_id}", "Message soft-deleted")
    db.commit()
    return {"ok": True}


def list_memories(db: Session, user: User) -> list[dict]:
    now = now_utc()
    rows = (
        db.query(AssistantMemory)
        .filter(AssistantMemory.owner_user_id == user.id, AssistantMemory.active.is_(True),
                AssistantMemory.deleted_at.is_(None), AssistantMemory.expires_at > now)
        .order_by(AssistantMemory.created_at.desc()).limit(MEMORY_MAX_ITEMS).all()
    )
    return [_memory_dict(row) for row in rows]


def _memory_dict(memory: AssistantMemory) -> dict:
    return {
        "id": memory.public_id, "conversation_id": memory.conversation_id,
        "memory_type": memory.memory_type, "content": memory.content, "scope": memory.scope.value,
        "creation_method": memory.creation_method.value, "confidence": memory.confidence,
        "created_at": memory.created_at, "expires_at": memory.expires_at,
    }


def create_memory(db: Session, user: User, *, content: str, memory_type: str,
                  scope: MemoryScope, conversation_id: str | None, expires_at: datetime | None,
                  source_message_id: str | None = None) -> dict:
    if scope == MemoryScope.CONVERSATION:
        if not conversation_id:
            raise HTTPException(status_code=422, detail="Conversation-scoped memory requires conversation_id")
        conversation = _conversation(db, conversation_id, user)
        internal_conversation_id = conversation.id
    else:
        internal_conversation_id = None
    internal_source_message_id = None
    if source_message_id:
        source = db.query(AssistantMessage).filter(
            AssistantMessage.public_id == source_message_id,
            AssistantMessage.deleted_at.is_(None),
        ).first()
        if not source or not conversation_id or source.conversation_id != internal_conversation_id:
            raise HTTPException(status_code=404, detail="Source message not found")
        internal_source_message_id = source.id
    expiry = expires_at or _expiry(MEMORY_RETENTION_DAYS)
    if expiry <= now_utc():
        raise HTTPException(status_code=422, detail="Memory expiry must be in the future")
    memory = AssistantMemory(
        owner_user_id=user.id, conversation_id=internal_conversation_id, memory_type=memory_type[:80],
        content=content, scope=scope, creation_method=MemoryCreationMethod.USER_CREATED,
        source_message_id=internal_source_message_id, expires_at=expiry, active=True,
    )
    db.add(memory)
    db.flush()
    db.commit()
    return _memory_dict(memory)


def delete_memory(db: Session, public_id: str, user: User) -> dict:
    memory = db.query(AssistantMemory).filter(
        AssistantMemory.public_id == public_id, AssistantMemory.owner_user_id == user.id,
        AssistantMemory.deleted_at.is_(None),
    ).first()
    if not memory:
        raise HTTPException(status_code=404, detail="Memory not found")
    memory.active = False
    memory.deleted_at = now_utc()
    _event(db, "memory", memory.public_id, RetentionEventType.MEMORY_DELETED, user)
    log_action(db, user, "assistant.memory_deleted", f"memory:{memory.public_id}", "Memory soft-deleted")
    db.commit()
    return {"ok": True}


def context_for(db: Session, conversation: AssistantConversation, user: User) -> tuple[list[dict], list[str]]:
    now = now_utc()
    messages = (
        db.query(AssistantMessage)
        .filter(AssistantMessage.conversation_id == conversation.id, AssistantMessage.deleted_at.is_(None),
                AssistantMessage.expires_at > now)
        .order_by(AssistantMessage.sequence.desc()).limit(CONTEXT_MAX_MESSAGES).all()
    )
    history: list[dict] = []
    characters = 0
    for message in reversed(messages):
        remaining = CONTEXT_MAX_CHARACTERS - characters
        if remaining <= 0:
            break
        content = message.content[:remaining]
        history.append({"role": message.role.value, "content": content})
        characters += len(content)
    memories = (
        db.query(AssistantMemory).filter(
            AssistantMemory.owner_user_id == user.id, AssistantMemory.active.is_(True),
            AssistantMemory.deleted_at.is_(None), AssistantMemory.expires_at > now,
            (AssistantMemory.scope == MemoryScope.USER) |
            ((AssistantMemory.scope == MemoryScope.CONVERSATION) & (AssistantMemory.conversation_id == conversation.id)),
        ).order_by(AssistantMemory.created_at.desc()).limit(MEMORY_MAX_ITEMS).all()
    )
    return history, [memory.content for memory in memories]


def next_sequence(db: Session, conversation: AssistantConversation) -> int:
    value = db.query(func.max(AssistantMessage.sequence)).filter(
        AssistantMessage.conversation_id == conversation.id
    ).scalar()
    return int(value or 0) + 1

