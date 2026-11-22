# Ejecuta los controles locales y guarda las salidas en evidence\local\
# Uso (desde la raíz del proyecto): .\scripts\run_checks.ps1
$ErrorActionPreference = "Continue"
$out = "evidence\local"
New-Item -ItemType Directory -Force $out | Out-Null
New-Item -ItemType Directory -Force reports | Out-Null

function Step($title) { Write-Host "`n=== $title ===" -ForegroundColor Cyan }

Step "pytest"
& .\.venv\Scripts\python.exe -m pytest --junitxml="$out\pytest.xml" 2>&1 | Tee-Object "$out\pytest.txt"
Copy-Item reports\trazabilidad_requisitos.csv "$out\trazabilidad_requisitos.csv" -ErrorAction SilentlyContinue

Step "semgrep: pruebas de la regla propia"
& .\.venv-tools\Scripts\semgrep.exe --test --metrics=off semgrep\rules 2>&1 | Tee-Object "$out\semgrep-test.txt"

Step "semgrep: reglas propias sobre app/"
& .\.venv-tools\Scripts\semgrep.exe scan --config semgrep\rules --metrics=off --severity ERROR --json-output="$out\semgrep-propias.json" app 2>&1 | Tee-Object "$out\semgrep-propias.txt"

Step "semgrep: reglas comunitarias (advertencia)"
& .\.venv-tools\Scripts\semgrep.exe scan --config p/python --metrics=off --json-output="$out\semgrep-comunitarias.json" app 2>&1 | Tee-Object "$out\semgrep-comunitarias.txt"

Step "pip-audit"
& .\.venv-tools\Scripts\pip-audit.exe -r requirements.txt -f json -o "$out\pip-audit.json" 2>&1 | Tee-Object "$out\pip-audit.txt"
& .\.venv-tools\Scripts\python.exe scripts\sca_gate.py "$out\pip-audit.json" 2>&1 | Tee-Object "$out\sca-gate.txt"

Step "SBOM CycloneDX"
if (-not (Test-Path .venv-sbom)) { python -m venv .venv-sbom }
& .\.venv-sbom\Scripts\python.exe -m pip install -q -r requirements.txt
& .\.venv-tools\Scripts\cyclonedx-py.exe environment .venv-sbom\Scripts\python.exe --sv 1.6 --of JSON --mc-type application --validate -o "$out\sbom.cdx.json"
& .\.venv-tools\Scripts\python.exe scripts\validate_sbom.py "$out\sbom.cdx.json" 2>&1 | Tee-Object "$out\sbom-validacion.txt"

Step "checkov: infraestructura insegura (se espera FALLO)"
& .\.venv-checkov\Scripts\checkov.exe -d lab\infra-insegura --framework terraform --compact 2>&1 | Tee-Object "$out\checkov-insegura.txt"
Step "checkov: infraestructura corregida (se espera APROBADO)"
& .\.venv-checkov\Scripts\checkov.exe -d infra --framework terraform --compact 2>&1 | Tee-Object "$out\checkov-corregida.txt"
Step "checkov: Dockerfile"
& .\.venv-checkov\Scripts\checkov.exe -f Dockerfile --framework dockerfile --compact 2>&1 | Tee-Object "$out\checkov-dockerfile.txt"

if (Get-Command opa -ErrorAction SilentlyContinue) {
    Step "OPA: pruebas de la política"
    opa test policy -v 2>&1 | Tee-Object "$out\opa-test.txt"
    Step "OPA: entrada permitida (código esperado 0)"
    opa eval --fail-defined --format pretty --input deploy\deployment.json --data policy "data.apisegura.deploy.deny[_]" 2>&1 | Tee-Object "$out\opa-permitida.txt"
    "Código de salida: $LASTEXITCODE" | Tee-Object -Append "$out\opa-permitida.txt"
    Step "OPA: entrada denegada (código esperado 1)"
    opa eval --fail-defined --format pretty --input lab\deployment-insegura.json --data policy "data.apisegura.deploy.deny[_]" 2>&1 | Tee-Object "$out\opa-denegada.txt"
    "Código de salida: $LASTEXITCODE" | Tee-Object -Append "$out\opa-denegada.txt"
} else {
    Write-Warning "opa no está en el PATH: se omiten las pruebas de la política."
}

Write-Host "`nSalidas guardadas en $out" -ForegroundColor Green
