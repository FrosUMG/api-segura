"""Configuración leída del entorno. No existen secretos por defecto."""
import os


def get_jwt_secret() -> str:
    secret = os.environ.get("JWT_SECRET", "")
    if len(secret) < 32:
        raise RuntimeError(
            "JWT_SECRET no definido o demasiado corto (mínimo 32 caracteres). "
            "El secreto debe provenir del entorno."
        )
    return secret


def docs_enabled() -> bool:
    return os.environ.get("ENABLE_DOCS") == "1"
