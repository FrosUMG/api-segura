#!/usr/bin/env python3
"""Valida un SBOM CycloneDX JSON contra el esquema oficial y resume sus componentes.

Uso: python scripts/validate_sbom.py reports/sbom.cdx.json
Requiere el entorno de herramientas (.venv-tools): cyclonedx-bom incluye cyclonedx-python-lib.
"""
import json
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("Uso: validate_sbom.py <sbom.cdx.json>")
        return 2
    text = Path(argv[1]).read_text(encoding="utf-8")
    document = json.loads(text)

    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    spec = document.get("specVersion", "1.6")
    version = SchemaVersion.from_version(spec)
    error = JsonStrictValidator(version).validate_str(text)
    if error:
        print(f"SBOM INVÁLIDO (CycloneDX {spec}): {error}")
        return 1

    components = document.get("components", [])
    dependencies = document.get("dependencies", [])
    print(f"SBOM válido: CycloneDX {spec}, bomFormat={document.get('bomFormat')}")
    print(f"Componentes: {len(components)} | Relaciones de dependencia: {len(dependencies)}")
    for comp in sorted(components, key=lambda c: c.get("name", "").lower()):
        print(f"  - {comp.get('name')}=={comp.get('version')}  {comp.get('purl', '')}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
