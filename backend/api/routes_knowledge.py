from __future__ import annotations
from fastapi import APIRouter, Depends, File, Form, UploadFile
from sqlalchemy.orm import Session

from models.database import get_db, KnowledgeDoc, KBCategory, User
from auth.security import get_current_user, require_permission
from auth.audit import log_action
from api.schemas import KnowledgeDocCreate
from rag.document_ingestion import extract_upload, persist_chunks
from rag.query_engine import ensure_indexed

router = APIRouter()


@router.get("")
def list_docs(category: str | None = None, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    query = db.query(KnowledgeDoc)
    if category:
        query = query.filter(KnowledgeDoc.category == category)
    docs = query.order_by(KnowledgeDoc.updated_at.desc()).all()
    return {"docs": [
        {
            "id": d.id, "title": d.title, "category": d.category.value, "tags": d.tags,
            "created_by": d.created_by, "updated_at": d.updated_at,
            "chunk_count": len(d.chunks),
            "indexed_chunk_count": sum(1 for chunk in d.chunks if (chunk.metadata_json or {}).get("indexed", True)),
            "source_filename": (d.chunks[0].metadata_json or {}).get("source_filename") if d.chunks else None,
        }
        for d in docs
    ]}


@router.get("/{doc_id}")
def get_doc(doc_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    doc = db.get(KnowledgeDoc, doc_id)
    if not doc:
        raise HTTPException(404, "Document not found")
    return {
        "id": doc.id, "title": doc.title, "category": doc.category.value,
        "content": doc.content, "tags": doc.tags, "chunk_count": len(doc.chunks),
        "indexed_chunk_count": sum(1 for chunk in doc.chunks if (chunk.metadata_json or {}).get("indexed", True)),
        "source_filename": (doc.chunks[0].metadata_json or {}).get("source_filename") if doc.chunks else None,
    }


@router.post("")
def create_doc(payload: KnowledgeDocCreate, db: Session = Depends(get_db), user: User = Depends(require_permission("kb.write"))):
    try:
        category = KBCategory(payload.category)
    except ValueError:
        raise HTTPException(400, f"Invalid category. Must be one of {[c.value for c in KBCategory]}")
    doc = KnowledgeDoc(title=payload.title, category=category, content=payload.content, tags=payload.tags, created_by=user.username)
    db.add(doc)
    db.commit()
    db.refresh(doc)
    persist_chunks(db, doc, payload.content, "manual-entry.md", "text/markdown")
    db.commit()
    ensure_indexed(db, force=True)  # new doc should be retrievable by the RAG assistant immediately
    log_action(db, user, "kb.create", target=f"kb_doc:{doc.id}", details=payload.title)
    return {"id": doc.id}


@router.post("/upload")
async def upload_doc(
    file: UploadFile = File(...),
    title: str | None = Form(None),
    category: str = Form("playbook"),
    tags: str = Form(""),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission("kb.write")),
):
    try:
        doc_category = KBCategory(category)
    except ValueError:
        raise HTTPException(400, f"Invalid category. Must be one of {[c.value for c in KBCategory]}")

    filename, content = await extract_upload(file)
    document_title = (title or "").strip() or filename
    doc = KnowledgeDoc(
        title=document_title[:255],
        category=doc_category,
        content=content,
        tags=[tag.strip() for tag in tags.split(",") if tag.strip()],
        created_by=user.username,
    )
    db.add(doc)
    db.flush()
    ingestion = persist_chunks(db, doc, content, filename, file.content_type)
    db.commit()
    db.refresh(doc)
    ensure_indexed(db, force=True)
    log_action(db, user, "kb.upload", target=f"kb_doc:{doc.id}", details=filename)
    return {
        "id": doc.id, "title": doc.title, "filename": filename,
        "chunk_count": ingestion["total_chunks"],
        "indexed_chunk_count": ingestion["indexed_chunks"],
    }


@router.delete("/{doc_id}")
def delete_doc(doc_id: int, db: Session = Depends(get_db), user: User = Depends(require_permission("kb.write"))):
    doc = db.get(KnowledgeDoc, doc_id)
    if not doc:
        raise HTTPException(404, "Document not found")
    db.delete(doc)
    db.commit()
    ensure_indexed(db, force=True)
    log_action(db, user, "kb.delete", target=f"kb_doc:{doc_id}", details=doc.title)
    return {"ok": True}
