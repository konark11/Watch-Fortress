from __future__ import annotations
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from models.database import get_db, User
from auth.security import get_current_user
from api.schemas import AskRequest
from rag.query_engine import ask, ensure_indexed
from rag.llm_providers import get_provider, RAG_MODE
from security.login_analysis import analyze_login_failures

router = APIRouter()


@router.post("/ask")
def ask_assistant(payload: AskRequest, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return ask(db, payload.question, [turn.model_dump() for turn in payload.history])


@router.post("/reindex")
def reindex(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    ensure_indexed(db, force=True)
    return {"ok": True, "message": "Knowledge base reindexed."}


@router.get("/login-failures")
def login_failure_analysis(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Explain the previous UTC day's failed-login activity from audit data."""
    return analyze_login_failures(db)


@router.get("/status")
def rag_status(_: User = Depends(get_current_user)):
    provider = get_provider()
    return {"mode": RAG_MODE, "provider": provider.name}
