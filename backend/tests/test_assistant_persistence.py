from datetime import timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from assistant.retention import purge_expired
from assistant.service import (
    context_for, create_conversation, create_memory, delete_conversation,
    list_conversations, next_sequence, read_conversation,
)
from models.database import (
    AssistantMessage, AssistantRole, Base, MemoryScope, User, now_utc,
)


def session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def users(db):
    first = User(username="alice", hashed_password="x")
    second = User(username="bob", hashed_password="x")
    db.add_all([first, second])
    db.commit()
    return first, second


def test_conversation_ownership_and_soft_delete():
    db = session()
    alice, bob = users(db)
    conversation = create_conversation(db, alice)
    assert len(list_conversations(db, alice)) == 1
    assert list_conversations(db, bob) == []
    try:
        read_conversation(db, conversation["id"], bob)
    except Exception as exc:
        assert getattr(exc, "status_code", None) == 404
    else:
        raise AssertionError("cross-user conversation read was allowed")
    delete_conversation(db, conversation["id"], alice)
    assert list_conversations(db, alice) == []


def test_ordering_expiry_and_explicit_memory_context_limits():
    db = session()
    alice, _ = users(db)
    conversation = create_conversation(db, alice)
    from models.database import AssistantConversation
    internal = db.query(AssistantConversation).filter_by(public_id=conversation["id"]).one()
    for sequence, content in ((1, "first"), (2, "second")):
        db.add(AssistantMessage(
            conversation_id=internal.id, sequence=sequence, role=AssistantRole.USER,
            content=content, expires_at=now_utc() + timedelta(days=1),
        ))
    db.commit()
    history, memories = context_for(db, internal, alice)
    assert [item["content"] for item in history] == ["first", "second"]
    assert memories == []
    memory = create_memory(
        db, alice, content="Prefer concise remediation", memory_type="preference",
        scope=MemoryScope.USER,
        conversation_id=None, expires_at=now_utc() + timedelta(days=1),
    )
    assert memory["content"] == "Prefer concise remediation"
    assert "Prefer concise remediation" in context_for(db, internal, alice)[1]
    expired = db.query(AssistantMessage).filter_by(sequence=1, conversation_id=internal.id).one()
    expired.expires_at = now_utc() - timedelta(seconds=1)
    db.commit()
    assert [item["content"] for item in context_for(db, internal, alice)[0]] == ["second"]
    assert next_sequence(db, internal) == 3


def test_purge_event_does_not_duplicate_message_content():
    db = session()
    alice, _ = users(db)
    conversation = create_conversation(db, alice)
    from models.database import AssistantConversation, RetentionEvent
    internal = db.query(AssistantConversation).filter_by(public_id=conversation["id"]).one()
    db.add(AssistantMessage(
        conversation_id=internal.id, sequence=1, role=AssistantRole.USER,
        content="private question", expires_at=now_utc() - timedelta(seconds=1),
    ))
    db.commit()
    result = purge_expired(db, batch_size=1)
    assert result["messages"] == 1
    event = db.query(RetentionEvent).order_by(RetentionEvent.id.desc()).first()
    assert "private question" not in repr(event.details)
