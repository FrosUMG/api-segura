"""Autenticación y operaciones administrativas."""
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, status

from app import tracing
from app.config import get_jwt_secret
from app.db import get_db
from app.deps import require_admin
from app.schemas import LoginIn, TokenOut
from app.security import DUMMY_HASH, create_access_token, verify_password

router = APIRouter()


@router.post("/auth/login", response_model=TokenOut, tags=["auth"])
def login(payload: LoginIn, conn: sqlite3.Connection = Depends(get_db)):
    row = conn.execute(
        "SELECT id, password_hash, is_active FROM users WHERE username = ?",
        (payload.username,),
    ).fetchone()

    # Se verifica siempre un hash (real o de referencia) para igualar el costo temporal.
    stored = row["password_hash"] if row else DUMMY_HASH
    password_ok = verify_password(payload.password, stored)

    if row is None or not password_ok or not row["is_active"]:
        tracing.event("auth.login", result="denied")
        # Mensaje uniforme: no revela si el usuario existe o está desactivado.
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales inválidas")

    tracing.event("auth.login", result="ok", user_id=row["id"])
    return TokenOut(access_token=create_access_token(row["id"], get_jwt_secret()))


@router.post("/admin/users/{user_id}/deactivate", tags=["admin"])
def deactivate_user(
    user_id: int,
    admin: dict = Depends(require_admin),
    conn: sqlite3.Connection = Depends(get_db),
):
    # Regla de negocio: un administrador no puede desactivar su propia cuenta.
    if user_id == admin["id"]:
        tracing.event("business_rule", rule="no_self_deactivation", result="deny")
        raise HTTPException(status_code=400, detail="No se puede desactivar la propia cuenta")

    cursor = conn.execute("UPDATE users SET is_active = 0 WHERE id = ?", (user_id,))
    conn.commit()
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    tracing.event("db.update", table="users", user_id=user_id, change="is_active=0")
    return {"user_id": user_id, "is_active": False}
