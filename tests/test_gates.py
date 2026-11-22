"""Pruebas del mecanismo de bloqueo de SCA (la política produce un fallo efectivo del proceso)."""
import importlib.util
import json
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "sca_gate", Path(__file__).resolve().parent.parent / "scripts" / "sca_gate.py"
)
sca_gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sca_gate)


def _write(tmp_path, dependencies):
    path = tmp_path / "pip-audit.json"
    path.write_text(json.dumps({"dependencies": dependencies, "fixes": []}), encoding="utf-8")
    return str(path)


@pytest.mark.req("SR-06")
def test_sca_sin_vulnerabilidades_aprueba(tmp_path):
    report = _write(tmp_path, [{"name": "fastapi", "version": "1.0", "vulns": []}])
    assert sca_gate.main(["sca_gate.py", report]) == 0


@pytest.mark.req("SR-06")
def test_sca_vulnerabilidad_con_correccion_bloquea(tmp_path):
    vuln = {"id": "PYSEC-0000-0", "fix_versions": ["2.0"], "aliases": [], "description": "demo"}
    report = _write(tmp_path, [{"name": "paquete-demo", "version": "1.0", "vulns": [vuln]}])
    assert sca_gate.main(["sca_gate.py", report]) == 1


@pytest.mark.req("SR-06")
def test_sca_vulnerabilidad_sin_correccion_solo_advierte(tmp_path):
    vuln = {"id": "PYSEC-0000-1", "fix_versions": [], "aliases": [], "description": "demo"}
    report = _write(tmp_path, [{"name": "paquete-demo", "version": "1.0", "vulns": [vuln]}])
    assert sca_gate.main(["sca_gate.py", report]) == 0


@pytest.mark.req("SR-06")
def test_sca_reporte_ausente_falla_cerrado(tmp_path):
    assert sca_gate.main(["sca_gate.py", str(tmp_path / "no-existe.json")]) == 2
