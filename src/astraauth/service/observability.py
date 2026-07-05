from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from astraauth.core.config import (
    DEFAULT_ASTRAAUTH_HOME,
    AuthConfig,
    enforce_private_file_permissions,
    ensure_private_directory,
    write_private_text,
)

_METRICS_FILENAME = "observability-metrics.json"
_LOG_FILENAME = "astraauth-events.log"


@dataclass(frozen=True)
class ObservabilityMetricRecord:
    name: str
    value: int


@dataclass(frozen=True)
class ObservabilitySnapshot:
    home: Path
    service_name: str
    correlation_header_name: str
    structured_logging_enabled: bool
    metrics_enabled: bool
    log_path: Path
    metrics_path: Path
    counters: tuple[ObservabilityMetricRecord, ...]


def _logs_dir(*, home: Path | None = None) -> Path:
    return (home or DEFAULT_ASTRAAUTH_HOME) / "logs"


def _metrics_path(*, home: Path | None = None) -> Path:
    return _logs_dir(home=home) / _METRICS_FILENAME


def _log_path(*, home: Path | None = None) -> Path:
    return _logs_dir(home=home) / _LOG_FILENAME


def next_correlation_id(*, supplied: str | None = None) -> str:
    if supplied:
        return supplied
    return str(uuid4())


def record_metric(
    *,
    config: AuthConfig,
    name: str,
    value: int = 1,
    home: Path | None = None,
) -> None:
    if not config.observability.metrics_enabled:
        return
    path = _metrics_path(home=home)
    if path.exists():
        raw = json.loads(path.read_text(encoding="utf-8"))
    else:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError("metrics payload must be an object")
    current = raw.get(name, 0)
    if not isinstance(current, int):
        current = 0
    raw[name] = current + value
    write_private_text(path, json.dumps(raw, indent=2, sort_keys=True))


def record_event(
    *,
    config: AuthConfig,
    event_type: str,
    status: str,
    home: Path | None = None,
    correlation_id: str | None = None,
    details: dict[str, Any] | None = None,
    level: str = "INFO",
) -> None:
    if not config.observability.structured_logging_enabled:
        return
    payload = {
        "timestamp": datetime.now(tz=UTC).isoformat(),
        "service": config.observability.service_name,
        "environment": config.environment,
        "level": level.upper(),
        "event_type": event_type,
        "status": status,
        "correlation_id": correlation_id,
        "details": details or {},
    }
    path = _log_path(home=home)
    ensure_private_directory(path.parent)
    logger_name = f"astraauth.observability.{path.stem}"
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not any(
        isinstance(handler, logging.FileHandler) and Path(handler.baseFilename) == path
        for handler in logger.handlers
    ):
        handler = logging.FileHandler(path, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    logger.log(getattr(logging, level.upper(), logging.INFO), json.dumps(payload, sort_keys=True))
    enforce_private_file_permissions(path)


def observability_snapshot(
    *, config: AuthConfig, home: Path | None = None
) -> ObservabilitySnapshot:
    metrics_path = _metrics_path(home=home)
    raw: dict[str, Any] = {}
    if metrics_path.exists():
        loaded = json.loads(metrics_path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            raw = loaded
    counters = tuple(
        ObservabilityMetricRecord(name=str(name), value=int(value))
        for name, value in sorted(raw.items())
        if isinstance(value, int)
    )
    return ObservabilitySnapshot(
        home=home or DEFAULT_ASTRAAUTH_HOME,
        service_name=config.observability.service_name,
        correlation_header_name=config.observability.correlation_header_name,
        structured_logging_enabled=config.observability.structured_logging_enabled,
        metrics_enabled=config.observability.metrics_enabled,
        log_path=_log_path(home=home),
        metrics_path=metrics_path,
        counters=counters,
    )
