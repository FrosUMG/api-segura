#!/usr/bin/env python3
"""Puerta de SCA: aplica la política de la organización sobre la salida JSON de pip-audit.

Política (umbral definido):
  - BLOQUEO     : vulnerabilidad conocida con versión corregida disponible (existe remediación).
  - ADVERTENCIA : vulnerabilidad conocida sin versión corregida (se registra y se trata como riesgo aceptado temporal).

Uso: python scripts/sca_gate.py reports/pip-audit.json
Código de salida: 0 = sin bloqueos, 1 = bloqueo, 2 = reporte ausente o inválido.
"""
import json
import sys
from pathlib import Path


def evaluate(report: dict) -> tuple[list[str], list[str]]:
    blocking: list[str] = []
    warnings: list[str] = []
    for dep in report.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            label = f"{dep.get('name')}=={dep.get('version')} -> {vuln.get('id')}"
            fixes = vuln.get("fix_versions") or []
            if fixes:
                blocking.append(f"{label} (corregida en: {', '.join(fixes)})")
            else:
                warnings.append(f"{label} (sin versión corregida disponible)")
    return blocking, warnings


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("Uso: sca_gate.py <reporte-pip-audit.json>")
        return 2
    path = Path(argv[1])
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"::error::Reporte de pip-audit ausente o inválido ({exc})")
        return 2

    total = len(report.get("dependencies", []))
    blocking, warnings = evaluate(report)
    print(f"Dependencias evaluadas: {total}")
    for item in warnings:
        print(f"::warning::ADVERTENCIA SCA: {item}")
    for item in blocking:
        print(f"::error::BLOQUEO SCA: {item}")
    if blocking:
        print(f"Resultado: BLOQUEADO ({len(blocking)} vulnerabilidades con corrección disponible).")
        return 1
    print(f"Resultado: APROBADO ({len(warnings)} advertencias, 0 bloqueos).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
