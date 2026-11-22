# Guía para el modelo de amenazas en OWASP Threat Dragon (desktop)

Guardar el modelo como `docs/threat-model/api-segura.json` (versionado en el repositorio) y exportar el diagrama
como imagen para el informe (Figura 1). Si la exportación no está disponible, usar una captura del diagrama.

## 1. Elementos del diagrama (DFD)

| Tipo en Threat Dragon | Nombre | Descripción / activo |
|---|---|---|
| Actor externo | Cliente API | alice, bob (user) y admin; origen de credenciales y entradas no confiables |
| Proceso | API FastAPI | `app.main`, rutas de documentos y administración |
| Proceso | Autenticación JWT | `app.security` y `app.deps`: hash PBKDF2, emisión y validación de tokens |
| Almacén de datos | SQLite | tablas `users` y `documents`; activo principal (confidencialidad e integridad) |
| Actor externo | PyPI | origen de dependencias (cadena de suministro) |
| Actor externo | GitHub Actions | ejecuta pruebas, SAST, SCA, DAST y construcción de la imagen |

## 2. Flujos de datos

| Flujo | Datos | Protocolo |
|---|---|---|
| Cliente API -> API FastAPI | credenciales, token Bearer, JSON, parámetro `q` | HTTP(S) |
| API FastAPI -> Autenticación JWT | credenciales, token | llamada interna |
| API FastAPI -> SQLite | consultas SQL parametrizadas, filas | sqlite3 local |
| PyPI -> GitHub Actions | paquetes (`pip install`) | HTTPS |
| GitHub Actions -> API FastAPI (laboratorio) | solicitudes de ZAP Baseline | HTTP, solo en el runner |

## 3. Límites de confianza

1. **Red del cliente | API:** todo lo que cruza es entrada no confiable.
2. **API | Persistencia:** la API es la única que accede a SQLite.
3. **Proveedores externos (PyPI) | Entorno de desarrollo y CI:** componentes de terceros que se incorporan al build.

## 4. Amenazas candidatas (completar activo, condición de riesgo, impacto y control; STRIDE)

| ID | Amenaza | Activo | Condición de riesgo | Impacto | Control propuesto / estado |
|----|---------|--------|---------------------|---------|----------------------------|
| T1 | BOLA/IDOR en `GET /documents/{id}` (Divulgación de información) | Documentos de usuarios | Ausencia de verificación de propietario | Lectura de documentos ajenos | Verificación de propietario; SR-02 (implementado y probado) |
| T2 | Inyección SQL en `GET /documents/search` (Manipulación / Divulgación) | Base SQLite | Consulta construida por interpolación | Lectura o alteración de datos | Consultas parametrizadas; regla Semgrep; SR-04 (implementado y probado) |
| T3 | Token JWT forjado, expirado o con `alg=none` (Suplantación) | Identidad y sesiones | Validación laxa del token o secreto débil | Suplantación de usuarios | Algoritmo fijado, `exp` obligatorio, secreto desde entorno; SR-01 (implementado y probado) |
| T4 | Escalada de privilegios a rutas de administración (Elevación) | Cuentas y roles | Falta de control por rol | Desactivación indebida de usuarios | `require_admin`; SR-03 (implementado y probado) |
| T5 | Dependencia vulnerable o comprometida (Manipulación de la cadena de suministro) | Integridad del build y la aplicación | Paquetes o acciones de CI no verificados | Ejecución de código no autorizado | pip-audit, SBOM, versiones fijadas; fijar acciones por SHA (pendiente) |
| T6 | Fuerza bruta contra `/auth/login` (Suplantación / Denegación de servicio) | Cuentas de usuario | Sin límite de intentos | Adivinación de credenciales | Limitación de intentos o bloqueo temporal (NO implementado: riesgo residual) |

## 5. Pasos en la herramienta

1. *New model*: título `api-segura`, tipo de diagrama STRIDE.
2. Dibujar elementos, flujos y los tres límites de confianza (*Trust boundary*).
3. Seleccionar cada elemento y registrar las amenazas de la sección 4 con su estado (*Open* / *Mitigated*).
4. Guardar el JSON en `docs/threat-model/` y exportar el diagrama.
