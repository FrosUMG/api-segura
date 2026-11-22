"""Dependencias de autenticación y autorización por rol."""
import sqlite3

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app import tracing
from app.config import get_jwt_secret
from app.db import get_db
from app.security import decode_access_token

bearer_scheme = HTTPBearer(auto_error=False)


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No autenticado",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    conn: sqlite3.Connection = Depends(get_db),
) -> dict:
    if credentials is None:
        tracing.event("auth.token", result="missing")
        raise _unauthorized()
    try:
        claims = decode_access_token(credentials.credentials, get_jwt_secret())
        user_id = int(claims["sub"])
    except (jwt.PyJWTError, ValueError, KeyError):
        tracing.event("auth.token", result="invalid")
        raise _unauthorized()

    row = conn.execute(
        "SELECT id, username, role, is_active FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if row is None or not row["is_active"]:
        tracing.event("auth.token", result="unknown_or_inactive_user")
        raise _unauthorized()

    tracing.event("auth.token", result="valid", user_id=row["id"], role=row["role"])
    return dict(row)


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] != "admin":
        tracing.event("authz.role_check", required="admin", actual=user["role"], result="deny")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permisos insuficientes")
    tracing.event("authz.role_check", required="admin", actual=user["role"], result="allow")
    return user
