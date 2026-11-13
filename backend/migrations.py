"""Ordered, explicit database migrations."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone

from sqlalchemy import text

from models.database import Base, engine


MIGRATION_VERSION = 5


def _is_postgres(connection) -> bool:
    return connection.dialect.name == "postgresql"


def _migration_1(connection) -> None:
    Base.metadata.create_all(bind=connection)


def _migration_2(connection) -> None:
    if _is_postgres(connection):
        try:
            connection.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
        except Exception as exc:
            raise RuntimeError(
                "PostgreSQL pgvector is unavailable or the database user cannot "
                "create extensions; install pgvector and grant CREATE permission, "
                "then rerun migrations."
            ) from exc
        connection.execute(text("""
            CREATE TABLE IF NOT EXISTS rag_index_records (
                id BIGSERIAL PRIMARY KEY, source_type VARCHAR(80) NOT NULL,
                source_id VARCHAR(255) NOT NULL, chunk_index INTEGER NOT NULL DEFAULT 0,
                content_hash VARCHAR(64) NOT NULL, title VARCHAR(500) NOT NULL,
                content TEXT NOT NULL, metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                embedding vector(768), embedding_model VARCHAR(255) NOT NULL,
                embedding_revision VARCHAR(255), embedding_dimension INTEGER NOT NULL,
                embedding_implementation VARCHAR(120) NOT NULL, indexed_at TIMESTAMPTZ NOT NULL,
                source_updated_at TIMESTAMPTZ, deleted_at TIMESTAMPTZ,
                UNIQUE (source_type, source_id, chunk_index)
            )
        """))
        for statement in (
            "CREATE INDEX IF NOT EXISTS ix_rag_records_vector_hnsw ON rag_index_records USING hnsw (embedding vector_cosine_ops)",
            "CREATE INDEX IF NOT EXISTS ix_rag_records_fts ON rag_index_records USING gin (to_tsvector('simple', coalesce(title, '') || ' ' || coalesce(content, '')))",
            "CREATE INDEX IF NOT EXISTS ix_rag_records_source ON rag_index_records (source_type, source_id)",
            "CREATE INDEX IF NOT EXISTS ix_rag_records_hash ON rag_index_records (content_hash)",
            "CREATE INDEX IF NOT EXISTS ix_rag_records_metadata ON rag_index_records USING gin (metadata)",
        ):
            connection.execute(text(statement))
    else:
        connection.execute(text("""
            CREATE TABLE IF NOT EXISTS rag_index_records (
                id INTEGER PRIMARY KEY, source_type VARCHAR(80) NOT NULL,
                source_id VARCHAR(255) NOT NULL, chunk_index INTEGER NOT NULL DEFAULT 0,
                content_hash VARCHAR(64) NOT NULL, title VARCHAR(500) NOT NULL,
                content TEXT NOT NULL, metadata TEXT NOT NULL DEFAULT '{}',
                embedding_json TEXT, embedding_model VARCHAR(255) NOT NULL,
                embedding_revision VARCHAR(255), embedding_dimension INTEGER NOT NULL,
                embedding_implementation VARCHAR(120) NOT NULL, indexed_at TIMESTAMP NOT NULL,
                source_updated_at TIMESTAMP, deleted_at TIMESTAMP,
                UNIQUE (source_type, source_id, chunk_index)
            )
        """))
        for statement in (
            "CREATE INDEX IF NOT EXISTS ix_rag_records_source ON rag_index_records (source_type, source_id)",
            "CREATE INDEX IF NOT EXISTS ix_rag_records_hash ON rag_index_records (content_hash)",
        ):
            connection.execute(text(statement))
    run_id_column = "BIGSERIAL" if _is_postgres(connection) else "INTEGER"
    connection.execute(text(f"""
        CREATE TABLE IF NOT EXISTS rag_index_runs (
            id {run_id_column} PRIMARY KEY, public_id VARCHAR(36) NOT NULL UNIQUE,
            state VARCHAR(30) NOT NULL, records_scanned INTEGER NOT NULL DEFAULT 0,
            added INTEGER NOT NULL DEFAULT 0, updated INTEGER NOT NULL DEFAULT 0,
            unchanged INTEGER NOT NULL DEFAULT 0, deleted INTEGER NOT NULL DEFAULT 0,
            failed INTEGER NOT NULL DEFAULT 0, embedding_model VARCHAR(255),
            embedding_revision VARCHAR(255), embedding_dimension INTEGER,
            error_message VARCHAR(500), started_at TIMESTAMP NOT NULL, completed_at TIMESTAMP
        )
    """))


def _migration_3(connection) -> None:
    """Create conversation storage for databases already at revision 2."""
    statements = [
        """CREATE TABLE IF NOT EXISTS assistant_conversations (
            id SERIAL PRIMARY KEY, public_id VARCHAR(36) NOT NULL UNIQUE,
            owner_user_id INTEGER NOT NULL REFERENCES users(id),
            title VARCHAR(255) NOT NULL, status VARCHAR(30) NOT NULL,
            retention_policy_version VARCHAR(80) NOT NULL, metadata JSON NOT NULL DEFAULT '{}',
            created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL,
            last_message_at TIMESTAMP, expires_at TIMESTAMP NOT NULL, deleted_at TIMESTAMP
        )""",
        """CREATE TABLE IF NOT EXISTS assistant_messages (
            id SERIAL PRIMARY KEY, public_id VARCHAR(36) NOT NULL UNIQUE,
            conversation_id INTEGER NOT NULL REFERENCES assistant_conversations(id) ON DELETE CASCADE,
            sequence INTEGER NOT NULL, role VARCHAR(30) NOT NULL, content TEXT NOT NULL,
            citations JSON, provider VARCHAR(120), model VARCHAR(255), generation_metadata JSON,
            created_at TIMESTAMP NOT NULL, expires_at TIMESTAMP NOT NULL, deleted_at TIMESTAMP,
            CONSTRAINT uq_assistant_message_sequence UNIQUE (conversation_id, sequence)
        )""",
        """CREATE TABLE IF NOT EXISTS assistant_memories (
            id SERIAL PRIMARY KEY, public_id VARCHAR(36) NOT NULL UNIQUE,
            owner_user_id INTEGER NOT NULL REFERENCES users(id),
            conversation_id INTEGER REFERENCES assistant_conversations(id) ON DELETE SET NULL,
            memory_type VARCHAR(80) NOT NULL, content TEXT NOT NULL,
            source_message_id INTEGER REFERENCES assistant_messages(id) ON DELETE SET NULL,
            scope VARCHAR(30) NOT NULL, creation_method VARCHAR(40) NOT NULL, confidence FLOAT,
            created_at TIMESTAMP NOT NULL, expires_at TIMESTAMP NOT NULL,
            deleted_at TIMESTAMP, active BOOLEAN NOT NULL DEFAULT TRUE
        )""",
        """CREATE TABLE IF NOT EXISTS retention_events (
            id SERIAL PRIMARY KEY, subject_type VARCHAR(80) NOT NULL,
            subject_public_id VARCHAR(36) NOT NULL, event_type VARCHAR(50) NOT NULL,
            actor_user_id INTEGER REFERENCES users(id), timestamp TIMESTAMP NOT NULL,
            details JSON NOT NULL DEFAULT '{}'
        )""",
    ]
    for statement in statements:
        if not _is_postgres(connection):
            statement = statement.replace("SERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT")
            statement = statement.replace(" JSON", " TEXT").replace("JSON,", "TEXT,")
            statement = statement.replace("DEFAULT TRUE", "DEFAULT 1")
        connection.execute(text(statement))


def _migration_4(connection) -> None:
    connection.execute(text("""
        CREATE TABLE IF NOT EXISTS worker_heartbeats (
            id INTEGER PRIMARY KEY,
            worker_id VARCHAR(160) NOT NULL UNIQUE,
            last_seen_at TIMESTAMP NOT NULL,
            status VARCHAR(30) NOT NULL DEFAULT 'alive',
            updated_at TIMESTAMP NOT NULL
        )
    """))
    connection.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_worker_heartbeats_last_seen ON worker_heartbeats (last_seen_at)"
    ))
    for statement in (
        "CREATE INDEX IF NOT EXISTS ix_assistant_conversations_owner_status ON assistant_conversations (owner_user_id, status)",
        "CREATE INDEX IF NOT EXISTS ix_assistant_conversations_expiry ON assistant_conversations (expires_at, deleted_at)",
        "CREATE INDEX IF NOT EXISTS ix_assistant_messages_expiry ON assistant_messages (expires_at, deleted_at)",
        "CREATE INDEX IF NOT EXISTS ix_assistant_messages_conversation_order ON assistant_messages (conversation_id, sequence)",
        "CREATE INDEX IF NOT EXISTS ix_assistant_memories_owner_active_expiry ON assistant_memories (owner_user_id, active, expires_at)",
        "CREATE INDEX IF NOT EXISTS ix_retention_events_subject_time ON retention_events (subject_type, subject_public_id, timestamp)",
    ):
        connection.execute(text(statement))


def _migration_5(connection) -> None:
    """Ensure PostgreSQL can generate IDs for RAG indexing runs."""
    if not _is_postgres(connection):
        return
    connection.execute(text(
        "CREATE SEQUENCE IF NOT EXISTS rag_index_runs_id_seq"
    ))
    connection.execute(text(
        "ALTER TABLE rag_index_runs "
        "ALTER COLUMN id SET DEFAULT nextval('rag_index_runs_id_seq')"
    ))
    connection.execute(text(
        "ALTER SEQUENCE rag_index_runs_id_seq OWNED BY rag_index_runs.id"
    ))
    connection.execute(text(
        "SELECT setval('rag_index_runs_id_seq', "
        "COALESCE((SELECT MAX(id) FROM rag_index_runs), 0) + 1, false)"
    ))


def migrate(target: int = MIGRATION_VERSION) -> int:
    if target < 1 or target > MIGRATION_VERSION:
        raise ValueError(f"Unsupported migration target: {target}")
    with engine.begin() as connection:
        connection.execute(text(
            "CREATE TABLE IF NOT EXISTS schema_migrations "
            "(version INTEGER PRIMARY KEY, applied_at TIMESTAMP NOT NULL)"
        ))
        applied = {row[0] for row in connection.execute(
            text("SELECT version FROM schema_migrations ORDER BY version")
        )}
        revisions = {
            1: _migration_1,
            2: _migration_2,
            3: _migration_3,
            4: _migration_4,
            5: _migration_5,
        }
        for version in range(1, target + 1):
            if version not in applied:
                revisions[version](connection)
                connection.execute(
                    text("INSERT INTO schema_migrations (version, applied_at) VALUES (:version, :now)"),
                    {"version": version, "now": datetime.now(timezone.utc)},
                )
    return target


def verify_current() -> None:
    with engine.connect() as connection:
        row = connection.execute(text("SELECT COALESCE(MAX(version), 0) FROM schema_migrations")).scalar_one_or_none()
        if int(row or 0) < MIGRATION_VERSION:
            raise RuntimeError("Database migrations are pending. Run `python -m migrations upgrade` before starting the PostgreSQL application.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Watch Fortress database migrations")
    parser.add_argument("command", choices=("upgrade", "current"))
    args = parser.parse_args()
    if args.command == "upgrade":
        print(f"Applied database migrations through revision {migrate()}.")
    else:
        with engine.connect() as connection:
            value = connection.execute(text("SELECT COALESCE(MAX(version), 0) FROM schema_migrations")).scalar_one_or_none()
        print(f"Current database revision: {int(value or 0)}")


if __name__ == "__main__":
    main()
