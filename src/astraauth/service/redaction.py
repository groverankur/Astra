from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import quote, unquote, urlsplit, urlunsplit

_REDACTED = "[REDACTED]"
_SECRET_KEY_PARTS = (
    "password",
    "passwd",
    "pwd",
    "token",
    "secret",
    "credential",
    "api_key",
    "apikey",
)
_SECRET_EXACT_KEYS = {"dsn", "password_hash", "token_hash", "client_secret"}


def redact_dsn(value: str) -> str:
    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.netloc:
        return value
    if parsed.password is None:
        return value
    username = quote(unquote(parsed.username or ""), safe="")
    hostname = parsed.hostname or ""
    password = quote(_REDACTED, safe="")
    auth = f"{username}:{password}@"
    if parsed.port is not None:
        netloc = f"{auth}{hostname}:{parsed.port}"
    else:
        netloc = f"{auth}{hostname}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


def redact_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _redact_mapping_value(str(key), item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_value(item) for item in value)
    return value


def _redact_mapping_value(key: str, value: Any) -> Any:
    key_lower = key.lower()
    if isinstance(value, str) and (key_lower == "dsn" or value_has_dsn_shape(value)):
        value = redact_dsn(value)
        if key_lower == "dsn":
            return value
    if key_lower in _SECRET_EXACT_KEYS or any(part in key_lower for part in _SECRET_KEY_PARTS):
        if isinstance(value, (Mapping, Sequence)) and not isinstance(
            value, (str, bytes, bytearray)
        ):
            return redact_value(value)
        return _REDACTED if value is not None else None
    return redact_value(value)


def value_has_dsn_shape(value: str) -> bool:
    parsed = urlsplit(value)
    return bool(parsed.scheme and parsed.netloc and parsed.password is not None)
