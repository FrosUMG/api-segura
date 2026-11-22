"""Pruebas de seguridad de la API.

Requisitos verificados (ver docs/requisitos.md):
  SR-01 Autenticación obligatoria con token válido
  SR-02 Autorización a nivel de objeto (BOLA/IDOR)
  SR-03 Control de acceso por rol y reglas de negocio
  SR-04 Validación de entradas y consultas parametrizadas
  SR-05 Gestión segura de credenciales, tokens y respuestas
"""
import time

import jwt
import pytest

from tests.conftest import CREDENTIALS, auth

pytestmark = pytest.mark.usefixtures("client")


# ----------------------------------------------------------------------------- SR-02
@pytest.mark.req("SR-02")
def test_acceso_legitimo_a_recurso_propio(client, tokens, alice_doc_ids):
    """Entrada: alice (token válido) solicita un documento suyo.
    Esperado: 200 y el propietario devuelto es alice."""
    response = client.get(f"/documents/{alice_doc_ids[0]}", headers=auth(tokens["alice"]))
    assert response.status_code == 200
    assert response.json()["id"] == alice_doc_ids[0]
    assert "alice" in response.json()["content"]


@pytest.mark.req("SR-02")
def test_denegacion_de_acceso_a_recurso_ajeno(client, tokens, bob_doc_id):
    """Entrada: alice solicita el documento de bob por su identificador.
    Esperado: 404 exacto y el cuerpo no contiene el contenido de bob (BOLA/IDOR bloqueado)."""
    response = client.get(f"/documents/{bob_doc_id}", headers=auth(tokens["alice"]))
    assert response.status_code == 404
    assert "SECRETO-BOB" not in response.text


@pytest.mark.req("SR-02")
def test_listado_solo_contiene_recursos_propios(client, tokens, bob_doc_id):
    """Entrada: alice lista sus documentos. Esperado: ninguno pertenece a bob."""
    response = client.get("/documents", headers=auth(tokens["alice"]))
    assert response.status_code == 200
    ids = [d["id"] for d in response.json()]
    assert bob_doc_id not in ids
    assert len({d["owner_id"] for d in response.json()}) == 1


@pytest.mark.req("SR-02")
def test_propietario_no_es_asignable_por_el_cliente(client, tokens):
    """Entrada: alice envía owner_id=999 en el cuerpo. Esperado: 422 (campo no permitido)."""
    response = client.post(
        "/documents",
        json={"title": "x", "content": "y", "owner_id": 999},
        headers=auth(tokens["alice"]),
    )
    assert response.status_code == 422


# ----------------------------------------------------------------------------- SR-01
@pytest.mark.req("SR-01")
def test_solicitud_sin_autenticacion(client):
    """Entrada: GET /documents sin cabecera Authorization. Esperado: 401 con WWW-Authenticate."""
    response = client.get("/documents")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.req("SR-01")
def test_token_con_firma_alterada(client, tokens):
    """Entrada: token válido con la firma modificada. Esperado: 401."""
    header, payload, signature = tokens["alice"].split(".")
    tampered = f"{header}.{payload}.{signature[:-3]}abc"
    assert client.get("/documents", headers=auth(tampered)).status_code == 401


@pytest.mark.req("SR-01")
def test_token_expirado(client):
    """Entrada: token firmado con el secreto correcto pero expirado. Esperado: 401."""
    import os

    now = int(time.time())
    expired = jwt.encode({"sub": "1", "iat": now - 7200, "exp": now - 3600}, os.environ["JWT_SECRET"], algorithm="HS256")
    assert client.get("/documents", headers=auth(expired)).status_code == 401


@pytest.mark.req("SR-01")
def test_token_con_algoritmo_none_rechazado(client):
    """Entrada: token sin firma (alg=none) que se presenta como alice. Esperado: 401."""
    forged = jwt.encode({"sub": "1", "exp": int(time.time()) + 3600}, key=None, algorithm="none")
    assert client.get("/documents", headers=auth(forged)).status_code == 401


# ----------------------------------------------------------------------------- SR-04
@pytest.mark.req("SR-04")
def test_entrada_inesperada_es_rechazada(client, tokens):
    """Entradas: título de 101 caracteres y tipo incorrecto. Esperado: 422 en ambos casos."""
    too_long = client.post("/documents", json={"title": "a" * 101}, headers=auth(tokens["alice"]))
    wrong_type = client.post("/documents", json={"title": ["lista"]}, headers=auth(tokens["alice"]))
    assert too_long.status_code == 422
    assert wrong_type.status_code == 422


@pytest.mark.req("SR-04")
def test_busqueda_legitima_devuelve_solo_coincidencias_propias(client, tokens):
    """Entrada: alice busca 'Informe'. Esperado: 200 y exactamente un documento suyo."""
    response = client.get("/documents/search", params={"q": "Informe"}, headers=auth(tokens["alice"]))
    assert response.status_code == 200
    assert [d["title"] for d in response.json()] == ["Informe trimestral"]


@pytest.mark.req("SR-04")
def test_inyeccion_sql_en_busqueda_no_expone_datos_ajenos(client, tokens, bob_doc_id):
    """Entrada: payload de inyección SQL en q. Esperado: 200, sin documentos de bob (consulta parametrizada)."""
    payload = "zzz%' OR 1=1 --"
    response = client.get("/documents/search", params={"q": payload}, headers=auth(tokens["alice"]))
    assert response.status_code == 200
    assert bob_doc_id not in [d["id"] for d in response.json()]
    assert "SECRETO-BOB" not in response.text
    assert response.json() == []


# ----------------------------------------------------------------------------- SR-03
@pytest.mark.req("SR-03")
def test_operacion_administrativa_denegada_a_usuario_comun(client, tokens):
    """Entrada: alice (rol user) intenta desactivar a carol. Esperado: 403."""
    response = client.post("/admin/users/3/deactivate", headers=auth(tokens["alice"]))
    assert response.status_code == 403


@pytest.mark.req("SR-03")
def test_administrador_no_puede_desactivarse_a_si_mismo(client, tokens):
    """Regla de negocio. Entrada: admin (id 4) se desactiva. Esperado: 400."""
    response = client.post("/admin/users/4/deactivate", headers=auth(tokens["admin"]))
    assert response.status_code == 400


@pytest.mark.req("SR-03")
def test_administrador_desactiva_usuario_y_se_bloquea_su_acceso(client, tokens):
    """Entrada: admin desactiva a carol. Esperado: 200; el token previo de carol y su login dejan de funcionar."""
    response = client.post("/admin/users/3/deactivate", headers=auth(tokens["admin"]))
    assert response.status_code == 200
    assert response.json() == {"user_id": 3, "is_active": False}
    assert client.get("/documents", headers=auth(tokens["carol"])).status_code == 401
    relogin = client.post("/auth/login", json={"username": "carol", "password": CREDENTIALS["carol"]})
    assert relogin.status_code == 401


# ----------------------------------------------------------------------------- SR-05
@pytest.mark.req("SR-05")
def test_login_no_revela_si_el_usuario_existe(client):
    """Entradas: usuario inexistente vs. contraseña errónea. Esperado: respuestas idénticas (401)."""
    unknown = client.post("/auth/login", json={"username": "no-existe", "password": "x"})
    wrong = client.post("/auth/login", json={"username": "alice", "password": "incorrecta"})
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json()


@pytest.mark.req("SR-05")
def test_contrasenas_almacenadas_con_hash_pbkdf2(client):
    """Esperado: ninguna contraseña en claro en la base y formato pbkdf2_sha256 con 600000 iteraciones."""
    import sqlite3
    import os

    conn = sqlite3.connect(os.environ["DB_PATH"])
    hashes = [row[0] for row in conn.execute("SELECT password_hash FROM users")]
    conn.close()
    assert hashes and all(h.startswith("pbkdf2_sha256$600000$") for h in hashes)
    assert not any(pw in h for h in hashes for pw in CREDENTIALS.values())


@pytest.mark.req("SR-05")
def test_cabeceras_de_seguridad_presentes(client):
    """Esperado: cabeceras defensivas en la respuesta de /health."""
    response = client.get("/health")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'"
    assert response.headers["cache-control"] == "no-store"
