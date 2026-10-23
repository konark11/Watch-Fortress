from __future__ import annotations
from sqlalchemy.orm import Session
from models.database import AuditLog, User


def log_action(
    db: Session,
    user: User | None,
    action: str,
    target: str = "",
    details: str = "",
    ip_address: str = "",
    username: str | None = None,
):
    entry = AuditLog(
        user_id=user.id if user else None,
        username=username or (user.username if user else "system"),
        action=action,
        target=target,
        details=details,
        ip_address=ip_address,
    )
    db.add(entry)
    db.commit()
