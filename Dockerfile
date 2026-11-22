# Imagen base: python:3.12-slim (Debian, variante reducida).
# Justificación: superficie de ataque menor que la imagen completa y compatibilidad con ruedas binarias
# (pydantic-core) que en Alpine/musl requieren compilación. La versión 3.12 cumple el mínimo de FastAPI (>=3.11).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /srv

# Solo dependencias de ejecución (sin pytest/httpx): componentes estrictamente necesarios.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Privilegios mínimos: usuario sin shell ni home, propietario únicamente del directorio de datos.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin appuser \
    && mkdir /data \
    && chown appuser /data

USER 10001

ENV DB_PATH=/data/app.db
# JWT_SECRET NO se define en la imagen: debe inyectarse en tiempo de ejecución.

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
