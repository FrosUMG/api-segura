"""Datos DEMO ficticios de laboratorio. No usar en ningún entorno real."""
from app.security import hash_password

DEMO_USERS = [
    # (username, password ficticia, rol)
    ("alice", "Alice-Lab-2026!", "user"),
    ("bob", "Bob-Lab-2026!", "user"),
    ("carol", "Carol-Lab-2026!", "user"),
    ("admin", "Admin-Lab-2026!", "admin"),
]

DEMO_DOCUMENTS = [
    ("alice", "Informe trimestral", "Contenido confidencial de alice."),
    ("alice", "Notas de reunión", "Notas internas de alice."),
    ("bob", "Contrato proveedor", "SECRETO-BOB: condiciones comerciales de bob."),
]


def seed_demo_data(conn) -> None:
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0:
        return
    for username, password, role in DEMO_USERS:
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, hash_password(password), role),
        )
    for owner, title, content in DEMO_DOCUMENTS:
        owner_id = conn.execute("SELECT id FROM users WHERE username = ?", (owner,)).fetchone()[0]
        conn.execute(
            "INSERT INTO documents (owner_id, title, content) VALUES (?, ?, ?)",
            (owner_id, title, content),
        )
