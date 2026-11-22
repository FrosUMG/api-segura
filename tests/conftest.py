import csv
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

TRACE_RESULTS: list[tuple[str, str, str]] = []

CREDENTIALS = {
    "alice": "Alice-Lab-2026!",
    "bob": "Bob-Lab-2026!",
    "carol": "Carol-Lab-2026!",
    "admin": "Admin-Lab-2026!",
}


@pytest.fixture(scope="session")
def client(tmp_path_factory):
    os.environ["DB_PATH"] = str(tmp_path_factory.mktemp("db") / "test.db")
    os.environ["JWT_SECRET"] = "secreto-solo-para-pruebas-" + "x" * 32
    from app.main import create_app

    with TestClient(create_app()) as test_client:
        yield test_client


def _login(client, username: str) -> str:
    response = client.post("/auth/login", json={"username": username, "password": CREDENTIALS[username]})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


@pytest.fixture(scope="session")
def tokens(client):
    return {name: _login(client, name) for name in CREDENTIALS}


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="session")
def alice_doc_ids(client, tokens):
    return [d["id"] for d in client.get("/documents", headers=auth(tokens["alice"])).json()]


@pytest.fixture(scope="session")
def bob_doc_id(client, tokens):
    return client.get("/documents", headers=auth(tokens["bob"])).json()[0]["id"]


# --- Trazabilidad requisito -> prueba -> resultado -------------------------------------------
@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if report.when == "call":
        marker = item.get_closest_marker("req")
        TRACE_RESULTS.append((marker.args[0] if marker else "-", item.nodeid, report.outcome))


def pytest_sessionfinish(session, exitstatus):
    if not TRACE_RESULTS:
        return
    out = Path("reports")
    out.mkdir(exist_ok=True)
    with open(out / "trazabilidad_requisitos.csv", "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["requisito", "prueba", "resultado"])
        writer.writerows(sorted(TRACE_RESULTS))
