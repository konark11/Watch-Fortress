"""
Authentication & Role-Based Access Control.

Four roles as specified:
  administrator       - full access, including user management
  security_analyst    - manage assets/scans/findings/reports, no user admin
  penetration_tester  - launch scans, view findings, cannot manage users or delete audit history
  auditor             - read-only access to everything + audit log

JWT bearer tokens (stateless, no server-side session store needed - keeps
the platform simple to run in a single portable process).
"""
from __future__ import annotations
import os
from datetime import datetime, timedelta, timezone
from typing import Optional
from passlib.context import CryptContext
from jose import jwt, JWTError
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from models.database import get_db, User, Role

SECRET_KEY = os.environ.get("VULN_JWT_SECRET", "dev-secret-change-me-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8

# pbkdf2_sha256 rather than bcrypt: pure-Python (via hashlib), no C-extension
# version-compatibility issues (passlib's bcrypt backend detection breaks on
# newer bcrypt releases), and no external library version pinning needed -
# one less thing to go wrong in an air-gapped deployment.
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None


async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise credentials_exception
    payload = decode_token(token)
    if not payload:
        raise credentials_exception
    username = payload.get("sub")
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active:
        raise credentials_exception
    return user


# --- Permission matrix -----------------------------------------------------
# What each role is allowed to do. Kept as an explicit table (rather than
# scattering "if role == ..." checks through route handlers) so the whole
# access model is auditable in one place.
PERMISSIONS = {
    "scan.launch": {Role.ADMINISTRATOR, Role.SECURITY_ANALYST, Role.PENETRATION_TESTER},
    "scan.cancel": {Role.ADMINISTRATOR, Role.SECURITY_ANALYST, Role.PENETRATION_TESTER},
    "finding.write": {Role.ADMINISTRATOR, Role.SECURITY_ANALYST, Role.PENETRATION_TESTER},
    "asset.write": {Role.ADMINISTRATOR, Role.SECURITY_ANALYST},
    "report.generate": {Role.ADMINISTRATOR, Role.SECURITY_ANALYST, Role.AUDITOR},
    "kb.write": {Role.ADMINISTRATOR, Role.SECURITY_ANALYST},
    "ti.write": {Role.ADMINISTRATOR, Role.SECURITY_ANALYST},
    "schedule.write": {Role.ADMINISTRATOR, Role.SECURITY_ANALYST},
    "user.manage": {Role.ADMINISTRATOR},
    "audit.view": {Role.ADMINISTRATOR, Role.AUDITOR},
}


def require_permission(permission: str):
    async def _checker(user: User = Depends(get_current_user)) -> User:
        allowed_roles = PERMISSIONS.get(permission, set())
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user.role.value}' does not have permission '{permission}'",
            )
        return user
    return _checker
