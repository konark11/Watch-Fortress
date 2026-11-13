from __future__ import annotations
from time import perf_counter
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from models.database import get_db, User
from auth.security import get_current_user
from rag.query_engine import production_retrieve
from rag.llm_providers import get_provider

router = APIRouter()


class ExperimentRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    configuration: str = Field(default="vector_rag", pattern="^(vector_rag|rag_llm)$")
    top_k: int = Field(default=5, ge=1, le=20)


@router.get("/configurations")
def configurations(_: User = Depends(get_current_user)):
    return {"configurations": [
        {"id": "vector_rag", "label": "Embedding vector retrieval only"},
        {"id": "rag_llm", "label": "RAG + configured LLM"},
    ]}


@router.post("/run")
def run_experiment(payload: ExperimentRequest, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
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
