from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from models.database import get_db, User, Role
from auth.security import hash_password, require_permission
from auth.audit import log_action
from api.schemas import UserCreate, UserOut, AdminResetPasswordRequest

router = APIRouter()


@router.get("", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), _: User = Depends(require_permission("user.manage"))):
    return db.query(User).all()


@router.post("", response_model=UserOut)
def create_user(payload: UserCreate, db: Session = Depends(get_db), admin: User = Depends(require_permission("user.manage"))):
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(400, "Username already exists")
    try:
        role = Role(payload.role)
    except ValueError:
        raise HTTPException(400, f"Invalid role. Must be one of {[r.value for r in Role]}")
    user = User(username=payload.username, email=payload.email, hashed_password=hash_password(payload.password), role=role)
    db.add(user)
    db.commit()
    db.refresh(user)
    log_action(db, admin, "user.create", target=f"user:{user.username}", details=f"role={role.value}")
    return user


@router.patch("/{user_id}/reset-password", response_model=UserOut)
def admin_reset_password(user_id: int, payload: AdminResetPasswordRequest, db: Session = Depends(get_db), admin: User = Depends(require_permission("user.manage"))):
    """Lets an administrator set a new password for a user who's locked
    out - this is the supported alternative to editing the database by
    hand. The user isn't shown their own new password anywhere; the admin
    who runs this must relay it to them through a separate, trusted channel."""
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    if len(payload.new_password) < 8:
        raise HTTPException(400, "New password must be at least 8 characters")
    user.hashed_password = hash_password(payload.new_password)
    db.commit()
    log_action(db, admin, "user.reset_password", target=f"user:{user.username}")
    return user


@router.patch("/{user_id}/deactivate", response_model=UserOut)
def deactivate_user(user_id: int, db: Session = Depends(get_db), admin: User = Depends(require_permission("user.manage"))):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    user.is_active = False
    db.commit()
    log_action(db, admin, "user.deactivate", target=f"user:{user.username}")
    return user


@router.patch("/{user_id}/role", response_model=UserOut)
def change_role(user_id: int, role: str, db: Session = Depends(get_db), admin: User = Depends(require_permission("user.manage"))):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    try:
        user.role = Role(role)
    except ValueError:
        raise HTTPException(400, f"Invalid role. Must be one of {[r.value for r in Role]}")
    db.commit()
    log_action(db, admin, "user.role_change", target=f"user:{user.username}", details=f"new_role={role}")
    return user
