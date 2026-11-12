"""Extract, chunk, and persist uploaded knowledge documents."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from fastapi import HTTPException, UploadFile
from sqlalchemy.orm import Session

from models.database import KnowledgeChunk, KnowledgeDoc
from rag.chunking import chunk_text
from rag.embeddings import embed_texts
from rag.relevance import clean_text, is_indexable, relevance_score


MAX_UPLOAD_BYTES = 10 * 1024 * 1024
SUPPORTED_EXTENSIONS = {".docx", ".pdf", ".md", ".markdown", ".txt"}


async def extract_upload(file: UploadFile) -> tuple[str, str]:
    filename = Path(file.filename or "").name
    extension = Path(filename).suffix.lower()
    if extension not in SUPPORTED_EXTENSIONS:
        allowed = ", ".join(sorted(SUPPORTED_EXTENSIONS))
        raise HTTPException(400, f"Unsupported document type. Allowed: {allowed}")

    raw = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "Document exceeds the 10 MB upload limit")
    if not raw:
        raise HTTPException(400, "Uploaded document is empty")

    try:
        if extension == ".docx":
            from io import BytesIO
            from docx import Document

            document = Document(BytesIO(raw))
            text = "\n\n".join(p.text.strip() for p in document.paragraphs if p.text.strip())
            for table in document.tables:
                rows = [" | ".join(cell.text.strip() for cell in row.cells) for row in table.rows]
                text += ("\n\n" if text else "") + "\n".join(row for row in rows if row.strip())
        elif extension == ".pdf":
            from io import BytesIO
            from pypdf import PdfReader

            reader = PdfReader(BytesIO(raw))
            text = "\n\n".join(page.extract_text() or "" for page in reader.pages).strip()
        else:
            text = raw.decode("utf-8-sig")
    except Exception as exc:
        raise HTTPException(400, f"Could not read {extension} document: {exc}") from exc

    text = clean_text(text)
    if not text.strip():
        raise HTTPException(400, "The document contains no extractable text")
    return filename, text.strip()


def persist_chunks(
    db: Session,
    document: KnowledgeDoc,
    text: str,
    filename: str,
    content_type: str | None,
) -> dict[str, int]:
    chunks = chunk_text(clean_text(text), strategy="sliding", size=400, overlap=50)
    timestamp = datetime.now(timezone.utc).isoformat()
    vectors = embed_texts(chunks)
    indexed_count = 0
    for index, (content, vector) in enumerate(zip(chunks, vectors)):
        score = relevance_score(content)
        indexed = is_indexable(content, score)
        db.add(KnowledgeChunk(
            document_id=document.id,
            chunk_index=index,
            content=content,
            embedding=vector,
            metadata_json={
                "source_filename": filename,
                "content_type": content_type or "application/octet-stream",
                "document_title": document.title,
                "category": document.category.value,
                "tags": document.tags or [],
                "ingested_at": timestamp,
                "relevance_score": score,
                "indexed": indexed,
                "processing_method": "local-extraction-and-relevance-filter",
            },
        ))
        indexed_count += int(indexed)
    return {"total_chunks": len(chunks), "indexed_chunks": indexed_count}
