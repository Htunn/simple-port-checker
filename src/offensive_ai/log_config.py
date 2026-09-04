"""
offensive-ai centralised logging configuration.

Features
--------
- Structured JSON formatter for machine-parseable log output
- ``contextvars``-based correlation IDs for tracing async scan operations
- Dedicated audit logger for authorized attack invocations (separate handler,
  always JSON, optionally persisted to a rotating file)

Quick start::

    from offensive_ai.log_config import configure_logging, new_correlation_id, audit_log

    configure_logging(level="INFO", fmt="json")

    cid = new_correlation_id()        # call once per scan/attack invocation
    result = await scanner.scan(...)  # all log lines emitted during the scan
                                      # carry the same correlation_id field
    audit_log("scan_completed", target="192.168.1.10", extra={"findings": 3})
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import uuid
from contextvars import ContextVar
from typing import Any

# ---------------------------------------------------------------------------
# Correlation-ID context variable (async-safe; each task gets its own value)
# ---------------------------------------------------------------------------
_correlation_id: ContextVar[str] = ContextVar("offensive_ai_correlation_id", default="")

AUDIT_LOGGER_NAME = "offensive_ai.audit"

# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------

_LOG_RECORD_BUILTIN_KEYS = frozenset(logging.LogRecord.__dict__.keys()) | {
    "message",
    "asctime",
    "args",
    "exc_info",
    "exc_text",
    "stack_info",
    "msg",
    "levelname",
    "levelno",
    "pathname",
    "filename",
    "module",
    "funcName",
    "created",
    "msecs",
    "relativeCreated",
    "thread",
    "threadName",
    "processName",
    "process",
    "name",
    "lineno",
    "taskName",
}


class JsonFormatter(logging.Formatter):
    """Emit each log record as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        record.message = record.getMessage()
        log_obj: dict[str, Any] = {
            "ts": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.message,
        }

        cid = _correlation_id.get("")
        if cid:
            log_obj["correlation_id"] = cid

        if record.exc_info:
            log_obj["exc"] = self.formatException(record.exc_info)

        if record.stack_info:
            log_obj["stack"] = self.formatStack(record.stack_info)

        # Append any extra fields passed via ``logger.info(..., extra={...})``
        for key, val in record.__dict__.items():
            if key not in _LOG_RECORD_BUILTIN_KEYS:
                log_obj[key] = val

        return json.dumps(log_obj, default=str)


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def new_correlation_id() -> str:
    """Generate a fresh correlation ID and bind it to the current async context.

    Call once at the start of each scan/attack invocation::

        cid = new_correlation_id()
        result = await scanner.scan(target)
        # all log lines emitted within this task now carry correlation_id=cid
    """
    cid = uuid.uuid4().hex[:16]
    _correlation_id.set(cid)
    return cid


def get_correlation_id() -> str:
    """Return the current context's correlation ID (empty string if unset)."""
    return _correlation_id.get("")


def get_audit_logger() -> logging.Logger:
    """Return the dedicated audit logger (``offensive_ai.audit``)."""
    return logging.getLogger(AUDIT_LOGGER_NAME)


def audit_log(
    event: str,
    target: str,
    *,
    mode: str = "",
    module: str = "",
    extra: dict[str, Any] | None = None,
) -> None:
    """Emit a structured audit-log entry for an authorized attack operation.

    Audit entries are always JSON-formatted and include the correlation ID,
    timestamp, event name, target, module, and mode.  They are emitted at
    ``INFO`` level on the ``offensive_ai.audit`` logger.

    Args:
        event:  Short event name, e.g. ``"attack_started"``, ``"scan_completed"``.
        target: Target host / IP address.
        mode:   Attack or scan mode (e.g. ``"safe"``, ``"deep"``).
        module: Name of the module emitting the event.
        extra:  Additional key-value pairs to include in the audit entry.
    """
    get_audit_logger().info(
        event,
        extra={
            "event_type": "audit",
            "event": event,
            "target": target,
            "mode": mode,
            "src_module": module,
            "correlation_id": get_correlation_id(),
            **(extra or {}),
        },
    )


# ---------------------------------------------------------------------------
# Package-level logging setup
# ---------------------------------------------------------------------------


def configure_logging(
    level: str = "WARNING",
    fmt: str = "text",
    audit_log_file: str | None = None,
) -> None:
    """Configure the ``offensive_ai`` logger hierarchy.

    Should be called once at process startup (e.g. from the CLI ``main()``
    or from ``OffensiveAIConfig`` initialisation).  Safe to call multiple times —
    duplicate handlers are not added.

    Args:
        level:         Minimum log level for offensive_ai loggers
                       (``DEBUG`` / ``INFO`` / ``WARNING`` / ``ERROR`` / ``CRITICAL``).
        fmt:           ``"text"`` for human-readable output, ``"json"`` for structured JSON.
        audit_log_file: Optional path to a rotating audit log file.  When ``None``
                        audit events are emitted to stderr.
    """
    numeric_level = getattr(logging, level.upper(), logging.WARNING)

    # --- Package root logger ------------------------------------------------
    root = logging.getLogger("offensive_ai")
    root.setLevel(numeric_level)

    if not root.handlers:
        handler: logging.Handler = logging.StreamHandler()
        if fmt == "json":
            handler.setFormatter(JsonFormatter())
        else:
            handler.setFormatter(
                logging.Formatter("%(asctime)s [%(levelname)-8s] %(name)s: %(message)s")
            )
        root.addHandler(handler)

    # --- Audit logger -------------------------------------------------------
    audit = logging.getLogger(AUDIT_LOGGER_NAME)
    audit.propagate = False  # Don't bubble up to root; audit has its own destination

    if not audit.handlers:
        if audit_log_file:
            fh = logging.handlers.RotatingFileHandler(
                audit_log_file,
                maxBytes=10 * 1024 * 1024,  # 10 MB
                backupCount=5,
                encoding="utf-8",
            )
            fh.setFormatter(JsonFormatter())
            audit.addHandler(fh)
        else:
            ah: logging.Handler = logging.StreamHandler()
            ah.setFormatter(JsonFormatter())
            audit.addHandler(ah)

    audit.setLevel(logging.INFO)
