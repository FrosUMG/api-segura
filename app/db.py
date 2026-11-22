"""Persistencia SQLite. Todas las consultas de la versión corregida son parametrizadas."""
import os
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL CHECK (role IN ('user', 'admin')),
    is_active     INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS documents (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    title    TEXT    NOT NULL,
    content  TEXT    NOT NULL DEFAULT ''
);
"""


def db_path() -> str:
    return os.environ.get("DB_PATH", "app.db")


def connect() -> sqlite3.Connection:
    # Una conexión por solicitud; no se comparte entre hilos de forma concurrente.
    conn = sqlite3.connect(db_path(), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_db():
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    from app.seed import seed_demo_data

    conn = connect()
    try:
        conn.executescript(SCHEMA)
        seed_demo_data(conn)
        conn.commit()
    finally:
        conn.close()
