# api-segura: auditoría, remediación y automatización de controles

API REST de laboratorio (FastAPI + SQLite) con autenticación JWT, dos identidades de usuario con recursos propios,
un rol administrador y un endpoint de búsqueda que procesa entradas del cliente.
Todo se ejecuta en un equipo local; los datos y las cuentas son ficticios.

> **Aviso:** la carpeta `lab/` contiene variantes deliberadamente vulnerables. Permanecen aisladas, no se ejecutan
> en el pipeline principal y **no deben exponerse a Internet**.

## 1. Estructura

```
app/                 API (versión CORREGIDA)
tests/               pruebas pytest (SR-01..SR-06) y trazabilidad requisito -> prueba
semgrep/rules/       regla propia de Semgrep + casos ruleid/ok
policy/              política OPA (Rego) y sus pruebas
infra/               Terraform corregido (se analiza con Checkov)
deploy/              descriptor de despliegue evaluado por OPA
scripts/             puerta de SCA, validación de SBOM, ejecución local de controles
.github/workflows/   pipeline de GitHub Actions (security.yml)
.zap/rules.tsv       umbrales de ZAP Baseline (FAIL vs WARN)
lab/                 AISLADO: parche vulnerable, Terraform inseguro, configuración insegura
docs/                requisitos, guía del modelo de amenazas
evidence/            evidencias de EJECUCIÓN propia (se completa al ejecutar los controles)
```

## 2. Instalación (Windows, PowerShell, desde la raíz del proyecto)

Requisitos: Python 3.11 o superior, Git y una cuenta de GitHub. Se usan **tres entornos virtuales** porque
Checkov y CycloneDX tienen dependencias incompatibles entre sí.

```powershell
# Si PowerShell bloquea la activación de entornos:
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
[Environment]::SetEnvironmentVariable('PYTHONUTF8','1','User')   # recomendado por Semgrep; reabrir la terminal

python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt

python -m venv .venv-tools
.\.venv-tools\Scripts\python.exe -m pip install semgrep pip-audit cyclonedx-bom

python -m venv .venv-checkov
.\.venv-checkov\Scripts\python.exe -m pip install checkov
```

OPA (binario único): descargar `opa_windows_amd64.exe` desde https://github.com/open-policy-agent/opa/releases,
guardarlo como `C:\tools\opa\opa.exe` y agregar esa carpeta al PATH.

En VS Code: `Ctrl+Shift+P` -> *Python: Select Interpreter* -> `.venv\Scripts\python.exe`. Usar la terminal integrada (PowerShell).

## 3. Ejecutar la API

```powershell
$env:JWT_SECRET  = [guid]::NewGuid().ToString("N") + [guid]::NewGuid().ToString("N")   # 64 caracteres, solo en esta sesión
$env:DB_PATH     = "lab.db"
$env:ENABLE_DOCS = "1"      # habilita /docs (Swagger UI) solo para uso manual local
$env:TRACE       = "1"      # trazas JSON del recorrido interno de cada solicitud
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Usuarios ficticios (ver `app/seed.py`): `alice`, `bob`, `carol` (rol user) y `admin` (rol admin).
Documentos iniciales: ids 1 y 2 pertenecen a alice; id 3 pertenece a bob.

```powershell
$base = "http://127.0.0.1:8000"
$t = (Invoke-RestMethod -Method Post "$base/auth/login" -ContentType application/json `
      -Body '{"username":"alice","password":"Alice-Lab-2026!"}').access_token
$h = @{ Authorization = "Bearer $t" }
Invoke-RestMethod "$base/documents" -Headers $h                         # documentos propios
Invoke-RestMethod "$base/documents/3" -Headers $h                       # ajeno: debe responder 404 (corregida)
$q = [uri]::EscapeDataString("zzz%' OR 1=1 --")
Invoke-RestMethod "$base/documents/search?q=$q" -Headers $h             # inyección: debe devolver []
```

## 4. Reproducir cada control (se guardan en `reports\`; copiar a `evidence\` lo que se entregue)

```powershell
New-Item -ItemType Directory -Force reports | Out-Null

# 3.3b Pruebas automatizadas + trazabilidad requisito->prueba (reports\trazabilidad_requisitos.csv)
.\.venv\Scripts\python.exe -m pytest --junitxml=reports\pytest.xml

# 3.2a/b Semgrep: pruebas de la regla propia y análisis de la aplicación
.\.venv-tools\Scripts\semgrep.exe --test --metrics=off semgrep\rules
.\.venv-tools\Scripts\semgrep.exe scan --config semgrep\rules --metrics=off --severity ERROR --error --json-output=reports\semgrep-propias.json app
.\.venv-tools\Scripts\semgrep.exe scan --config p/python --metrics=off --json-output=reports\semgrep-comunitarias.json app

# 3.2c SCA + puerta de umbral
.\.venv-tools\Scripts\pip-audit.exe -r requirements.txt -f json -o reports\pip-audit.json
.\.venv-tools\Scripts\python.exe scripts\sca_gate.py reports\pip-audit.json

# 3.2d SBOM CycloneDX (entorno solo con dependencias de ejecución) y su validación
python -m venv .venv-sbom
.\.venv-sbom\Scripts\python.exe -m pip install -r requirements.txt
.\.venv-tools\Scripts\cyclonedx-py.exe environment .venv-sbom\Scripts\python.exe --sv 1.6 --of JSON --mc-type application --validate -o reports\sbom.cdx.json
.\.venv-tools\Scripts\python.exe scripts\validate_sbom.py reports\sbom.cdx.json

# 3.6b Checkov: infraestructura insegura (debe FALLAR), corregida (debe PASAR) y Dockerfile
.\.venv-checkov\Scripts\checkov.exe -d lab\infra-insegura --framework terraform --compact
.\.venv-checkov\Scripts\checkov.exe -d infra --framework terraform --compact
.\.venv-checkov\Scripts\checkov.exe -f Dockerfile --framework dockerfile --compact

# 3.6c OPA: pruebas, entrada permitida (código 0) y denegada (código 1)
opa test policy -v
opa eval --fail-defined --format pretty --input deploy\deployment.json --data policy "data.apisegura.deploy.deny[_]"; $LASTEXITCODE
opa eval --fail-defined --format pretty --input lab\deployment-insegura.json --data policy "data.apisegura.deploy.deny[_]"; $LASTEXITCODE
```

`scripts\run_checks.ps1` ejecuta la secuencia anterior y guarda las salidas en `evidence\local\`.

**Mecanismo que convierte la denegación de OPA en fallo del proceso:** `opa eval --fail-defined` termina con código
distinto de 0 cuando `deny` contiene mensajes; el paso del workflow falla y la compuerta de liberación no se alcanza.

**Docker, Trivy y ZAP** se ejecutan en GitHub Actions (jobs `contenedor` y `dast`); no requieren Docker local.
Los informes quedan como artefactos de cada ejecución (pestaña *Actions* -> ejecución -> *Artifacts*).

## 5. Demostración de bloqueo y aprobación en CI (dos ejecuciones ligadas a commits)

Antes de empezar, crear en GitHub un repositorio vacío (sin README) y configurar `git config user.name` / `user.email`.

```powershell
git init -b main
git add .
git commit -m "chore: linea base corregida con controles de seguridad"
git remote add origin https://github.com/<usuario>/api-segura.git
git push -u origin main
```

1. **Verificar primero la ejecución en `main`** (pestaña *Actions*). Si algún job falla por motivos de infraestructura
   (p. ej. la versión `TRIVY_VERSION` del workflow), corregirlo ahora; así la ejecución roja posterior fallará por la razón correcta.
2. **Ejecución 1 (debe BLOQUEAR):**
   ```powershell
   git switch -c lab/vulnerable
   git apply lab/vulnerable.patch
   git commit -am "lab: reintroduce BOLA e inyeccion SQL (aislado, NO desplegar)"
   git push -u origin lab/vulnerable
   ```
   Esperado: fallan los jobs `pruebas` (2 pruebas) y `sast` (regla propia); `compuerta-liberacion` no se ejecuta.
3. **Ejecución 2 (debe APROBAR):**
   ```powershell
   git apply -R lab/vulnerable.patch
   git commit -am "fix: verifica propietario del documento y parametriza la busqueda"
   git push
   ```
   Registrar los hashes (`git log --oneline`) y los enlaces de ambas ejecuciones. Luego integrar a `main` mediante *pull request*.

## 6. Qué documentar con evidencia propia

| Sección | Evidencia que debe generar el estudiante |
|---|---|
| 3.1 | Modelo en Threat Dragon (`docs/threat-model/`), matriz de riesgos, requisitos (`docs/requisitos.md`) |
| 3.2 | `semgrep-*.json`, salida de `--test`, `pip-audit.json`, `sbom.cdx.json`, análisis del incidente con fuentes |
| 3.3 | Informe ZAP del job `dast`, `pytest.xml`, `trazabilidad_requisitos.csv`, traza de una solicitud (`TRACE=1`) |
| 3.4 | Reproducción manual en `lab/vulnerable`, respuesta observada, `git diff` antes/después, retest |
| 3.5 | Enlaces y hashes de las dos ejecuciones de Actions, `security.yml` |
| 3.6 | Log de `docker build` y informe de Trivy (artefactos de Actions), salidas de Checkov y OPA |

Las capturas deben provenir de las ejecuciones propias sobre el código entregado.

## 7. Limitaciones conocidas (declararlas en el informe)

- ZAP Baseline es **pasivo** y sin autenticación: no explota la inyección SQL y no alcanza rutas que exigen token.
- No hay límite de intentos en `/auth/login` (riesgo residual declarado en `docs/threat-model/`).
- Las acciones de GitHub se referencian por etiqueta de versión, no por SHA: fijarlas por SHA es un control pendiente.
- La suite emite una advertencia de deprecación de Starlette sobre `httpx`; no afecta a los resultados.
