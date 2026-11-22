"""API de laboratorio: gestión de documentos por usuario (FastAPI)."""
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request

from app import tracing
from app.config import docs_enabled, get_jwt_secret
from app.db import init_db
from app.routes_auth import router as auth_router
from app.routes_documents import router as documents_router

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Cross-Origin-Resource-Policy": "same-origin",
}
CSP_API = "default-src 'none'; frame-ancestors 'none'"


@asynccontextmanager
async def lifespan(app: FastAPI):
    get_jwt_secret()  # falla al iniciar si el secreto no está definido (configuración segura por defecto)
    init_db()
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="API de laboratorio - Documentos",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs" if docs_enabled() else None,
        redoc_url=None,
    )

    @app.middleware("http")
    async def add_headers_and_trace(request: Request, call_next):
        token = tracing.set_request_id(uuid.uuid4().hex[:8])
        try:
            tracing.event("http.in", method=request.method, path=request.url.path)
            response = await call_next(request)
            for name, value in SECURITY_HEADERS.items():
                response.headers[name] = value
            if request.url.path != "/docs":  # Swagger UI requiere recursos que la CSP estricta bloquea
                response.headers["Content-Security-Policy"] = CSP_API
            tracing.event("http.out", status=response.status_code)
            return response
        finally:
            tracing.reset_request_id(token)

    @app.get("/health", tags=["meta"])
    def health():
        return {"status": "ok"}

    app.include_router(auth_router)
    app.include_router(documents_router)
    return app


app = create_app()
