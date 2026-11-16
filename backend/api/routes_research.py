from __future__ import annotations
from time import perf_counter
from typing import Any, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from models.database import get_db, User
from auth.security import get_current_user, oauth2_scheme, decode_token
from rag.query_engine import production_retrieve
from rag.llm_providers import get_provider
from rag.benchmark_experiment import load_benchmark_questions, compare_three_ways

router = APIRouter()


class ExperimentRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    configuration: str = Field(default="vector_rag", pattern="^(vector_rag|rag_llm)$")
    top_k: int = Field(default=5, ge=1, le=20)


class BenchmarkCompareRequest(BaseModel):
    question_id: Optional[str] = None
    question: Optional[str] = None
    gold_cve: Optional[str] = None
    top_k: int = Field(default=5, ge=1, le=15)


async def get_optional_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> Optional[User]:
    if not token:
        return None
    payload = decode_token(token)
    if not payload:
        return None
    username = payload.get("sub")
    return db.query(User).filter(User.username == username).first()


@router.get("/configurations")
def configurations(_: Optional[User] = Depends(get_optional_user)):
    return {"configurations": [
        {"id": "vector_rag", "label": "Embedding vector retrieval only"},
        {"id": "rag_llm", "label": "RAG + configured LLM"},
    ]}


@router.post("/run")
def run_experiment(payload: ExperimentRequest, db: Session = Depends(get_db), _: Optional[User] = Depends(get_optional_user)):
    started = perf_counter()
    retrieved = production_retrieve(db, payload.question, payload.top_k)
    result = {
        "configuration": payload.configuration,
        "question": payload.question,
        "retrieved": [{"id": d.get("id"), "source": d.get("source"), "title": d.get("title"), "score": score} for d, score in retrieved],
        "answer": None,
        "provider": None,
        "errors": [],
    }
    if payload.configuration == "rag_llm":
        provider = get_provider()
        result["provider"] = provider.name
        result["answer"] = provider.generate(payload.question, retrieved)
    result["latency_ms"] = round((perf_counter() - started) * 1000, 2)
    return result


@router.get("/benchmark-questions")
def get_benchmark_questions(_: Optional[User] = Depends(get_optional_user)):
    """Return all 86 benchmark evaluation questions with metadata."""
    questions = load_benchmark_questions()
    return {
        "count": len(questions),
        "questions": questions,
    }


@router.post("/benchmark-compare")
def run_benchmark_compare(
    payload: BenchmarkCompareRequest,
    db: Session = Depends(get_db),
    _: Optional[User] = Depends(get_optional_user),
):
    """Run interactive 3-way RAG comparison (Hybrid vs Hybrid+Reranker vs Hybrid+JEV)."""
    question_text = payload.question
    gold_cve = payload.gold_cve
    question_id = payload.question_id

    # If question_id is provided, resolve question and gold_cve from dataset
    meta = None
    if question_id:
        all_questions = load_benchmark_questions()
        matched = next((q for q in all_questions if q["question_id"] == question_id), None)
        if matched:
            question_text = matched["question"]
            gold_cve = matched["gold_answer"]
            meta = matched

    if not question_text:
        raise HTTPException(status_code=400, detail="Either question_id or question text must be provided.")

    comparison = compare_three_ways(
        db=db,
        question_text=question_text,
        gold_cve=gold_cve,
        top_k=payload.top_k,
    )
    if meta:
        comparison["metadata"] = meta

    return comparison
