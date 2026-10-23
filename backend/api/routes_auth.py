from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from models.database import get_db, User, Role
from auth.security import hash_password, verify_password, create_access_token, get_current_user, require_permission
from auth.audit import log_action
from api.schemas import Token, UserCreate, UserOut, ChangePasswordRequest

router = APIRouter()


@router.post("/login", response_model=Token)
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        log_action(
            db,
            user,
            "auth.login_failed",
            target=f"user:{form_data.username}",
            details="invalid_credentials",
            ip_address=request.client.host if request.client else "",
            username=form_data.username,
        )
        raise HTTPException(401, "Incorrect username or password")
    if not user.is_active:
        log_action(
            db,
            user,
            "auth.login_failed",
            target=f"user:{user.username}",
            details="inactive_account",
            ip_address=request.client.host if request.client else "",
        )
        raise HTTPException(403, "This account has been deactivated")

    from datetime import datetime, timezone
    user.last_login = datetime.now(timezone.utc)
    db.commit()

    token = create_access_token({"sub": user.username, "role": user.role.value})
    log_action(db, user, "auth.login", target=f"user:{user.username}", ip_address=request.client.host if request.client else "")
    return Token(access_token=token, role=user.role.value, username=user.username)


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user


@router.post("/change-password")
def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Self-service password change for a logged-in user. Requires the
    current password to prevent someone with a hijacked/left-open session
    from locking the real owner out."""
    if not verify_password(payload.current_password, user.hashed_password):
        raise HTTPException(401, "Current password is incorrect")
    if len(payload.new_password) < 8:
        raise HTTPException(400, "New password must be at least 8 characters")
    user.hashed_password = hash_password(payload.new_password)
    db.commit()
    log_action(db, user, "auth.change_password", target=f"user:{user.username}", ip_address=request.client.host if request.client else "")
    return {"detail": "Password updated successfully"}


@router.post("/bootstrap-admin", response_model=UserOut)
def bootstrap_admin(payload: UserCreate, db: Session = Depends(get_db)):
    """Creates the FIRST administrator account. Only works when there are
    zero users in the system - this is how a fresh air-gapped deployment
    gets its initial admin without needing an existing admin to create one
    (a chicken-and-egg problem every self-hosted platform has to solve)."""
    if db.query(User).count() > 0:
        raise HTTPException(403, "An administrator already exists. Ask them to create your account.")
    user = User(username=payload.username, email=payload.email, hashed_password=hash_password(payload.password), role=Role.ADMINISTRATOR)
    db.add(user)
    db.commit()
    db.refresh(user)
    log_action(db, user, "auth.bootstrap_admin", target=f"user:{user.username}")
    return user
