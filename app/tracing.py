"""Instrumentación local de trazas (NO es IAST).

Se activa con TRACE=1. Emite una línea JSON por evento con un identificador de solicitud,
lo que permite documentar el recorrido interno de una petición: entrada HTTP, autenticación,
verificación de permisos, operación sobre datos y respuesta.
"""
import contextvars
import json
import logging
import os
import sys
import time

_request_id: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")
_logger = logging.getLogger("apisegura.trace")

if not _logger.handlers:
    _handler = logging.StreamHandler(sys.stdout)
    _handler.setFormatter(logging.Formatter("%(message)s"))
    _logger.addHandler(_handler)
    _logger.setLevel(logging.INFO)
    _logger.propagate = False


def enabled() -> bool:
    return os.environ.get("TRACE") == "1"


def set_request_id(value: str):
    return _request_id.set(value)


def reset_request_id(token) -> None:
    _request_id.reset(token)


def event(step: str, **fields) -> None:
    if not enabled():
        return
    record = {"ts": round(time.time(), 3), "rid": _request_id.get(), "step": step, **fields}
    _logger.info(json.dumps(record, ensure_ascii=False))
