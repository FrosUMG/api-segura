"""Hash de contraseñas (PBKDF2-HMAC-SHA256, biblioteca estándar) y tokens JWT (PyJWT)."""
import hashlib
import hmac
import os
import time

import jwt

ITERATIONS = 600_000
ALGORITHM = "HS256"
TOKEN_TTL_SECONDS = 15 * 60


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    return f"pbkdf2_sha256${ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations, salt_hex, hash_hex = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest.hex(), hash_hex)


# Hash de referencia para igualar el costo cuando el usuario no existe (evita enumeración por tiempo).
DUMMY_HASH = hash_password("contrasena-de-referencia-no-valida")


def create_access_token(user_id: int, secret: str) -> str:
    now = int(time.time())
    payload = {"sub": str(user_id), "iat": now, "exp": now + TOKEN_TTL_SECONDS}
    return jwt.encode(payload, secret, algorithm=ALGORITHM)


def decode_access_token(token: str, secret: str) -> dict:
    # Algoritmo fijado explícitamente; "exp" y "sub" son obligatorios.
    return jwt.decode(token, secret, algorithms=[ALGORITHM], options={"require": ["exp", "sub"]})
