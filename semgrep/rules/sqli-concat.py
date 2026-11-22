# Casos de prueba de la regla apisegura-sql-dinamico-en-execute (se ejecutan con: semgrep --test semgrep/rules)
# "ruleid" = la regla DEBE reportar la línea siguiente. "ok" = la regla NO debe reportarla.
import sqlite3

conn = sqlite3.connect(":memory:")


def incumple_fstring_directo(q):
    # ruleid: apisegura-sql-dinamico-en-execute
    conn.execute(f"SELECT * FROM documents WHERE title LIKE '%{q}%'")


def incumple_fstring_en_variable(q, uid):
    sql = f"SELECT * FROM documents WHERE owner_id = {uid} AND title LIKE '%{q}%'"
    # ruleid: apisegura-sql-dinamico-en-execute
    return conn.execute(sql).fetchall()


def incumple_concatenacion_encadenada(q):
    # ruleid: apisegura-sql-dinamico-en-execute
    conn.execute("SELECT * FROM documents WHERE title = '" + q + "'")


def incumple_concatenacion_en_variable(q):
    sql = "SELECT * FROM documents WHERE title = '" + q + "'"
    # ruleid: apisegura-sql-dinamico-en-execute
    conn.execute(sql)


def incumple_format(q):
    # ruleid: apisegura-sql-dinamico-en-execute
    conn.execute("SELECT * FROM documents WHERE title = '{}'".format(q))


def incumple_porcentaje(q):
    # ruleid: apisegura-sql-dinamico-en-execute
    conn.execute("SELECT * FROM documents WHERE title = '%s'" % q)


def cumple_consulta_parametrizada(q, uid):
    # ok: apisegura-sql-dinamico-en-execute
    return conn.execute("SELECT * FROM documents WHERE owner_id = ? AND title LIKE ?", (uid, f"%{q}%")).fetchall()


def cumple_consulta_literal_en_variable(uid):
    sql = "SELECT * FROM documents WHERE owner_id = ?"
    # ok: apisegura-sql-dinamico-en-execute
    return conn.execute(sql, (uid,)).fetchall()


def cumple_concatenacion_de_constantes():
    # ok: apisegura-sql-dinamico-en-execute
    return conn.execute("SELECT COUNT(*) " + "FROM users").fetchone()


def cumple_consulta_literal_sin_parametros():
    # ok: apisegura-sql-dinamico-en-execute
    return conn.execute("SELECT COUNT(*) FROM users").fetchone()
