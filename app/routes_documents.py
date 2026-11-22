"""Recursos de usuario (documentos). *** VERSIÓN VULNERABLE DE LABORATORIO: NO DESPLEGAR ***.

Los defectos del laboratorio (BOLA/IDOR en get_document e inyección SQL en search_documents)
se reintroducen únicamente en la rama aislada `lab/vulnerable` mediante lab/vulnerable.patch.
"""
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Query

from app import tracing
from app.db import get_db
from app.deps import get_current_user
from app.schemas import DocumentIn, DocumentOut

router = APIRouter(prefix="/documents", tags=["documents"])


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@router.get("", response_model=list[DocumentOut])
def list_documents(user: dict = Depends(get_current_user), conn: sqlite3.Connection = Depends(get_db)):
    rows = conn.execute(
        "SELECT id, owner_id, title, content FROM documents WHERE owner_id = ? ORDER BY id", (user["id"],)
    ).fetchall()
    return [dict(r) for r in rows]


@router.post("", response_model=DocumentOut, status_code=201)
def create_document(
    payload: DocumentIn,
    user: dict = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_db),
):
    # El propietario siempre proviene de la identidad autenticada, nunca del cuerpo de la solicitud.
    cursor = conn.execute(
        "INSERT INTO documents (owner_id, title, content) VALUES (?, ?, ?)",
        (user["id"], payload.title, payload.content),
    )
    conn.commit()
    tracing.event("db.insert", table="documents", doc_id=cursor.lastrowid, owner_id=user["id"])
    return {"id": cursor.lastrowid, "owner_id": user["id"], "title": payload.title, "content": payload.content}


# Debe declararse antes que "/{doc_id}" para que "search" no se interprete como identificador.
@router.get("/search", response_model=list[DocumentOut])
def search_documents(
    q: str = Query(min_length=1, max_length=50),
    user: dict = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_db),
):
    tracing.event("db.query", operation="search", parametrized=False, owner_id=user["id"])
    sql = f"SELECT id, owner_id, title, content FROM documents WHERE owner_id = {user['id']} AND title LIKE '%{q}%' ORDER BY id"
    rows = conn.execute(sql).fetchall()
    return [dict(r) for r in rows]


@router.get("/{doc_id}", response_model=DocumentOut)
def get_document(
    doc_id: int,
    user: dict = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_db),
):
    row = conn.execute("SELECT id, owner_id, title, content FROM documents WHERE id = ?", (doc_id,)).fetchone()
    if row is None:
        tracing.event("db.query", operation="get_document", doc_id=doc_id, found=False)
        raise HTTPException(status_code=404, detail="Documento no encontrado")

    # (sin verificación de propietario)
    return dict(row)
