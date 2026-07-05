from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Literal, Protocol

HookName = Literal[
    "auth.pre_authenticate",
    "auth.post_authenticate",
    "auth.pre_authorize",
    "auth.post_authorize",
    "session.created",
    "token.issued",
    "mfa.challenge",
]

HookHandler = Callable[[dict[str, Any]], dict[str, Any] | None]
EndpointHandler = Callable[[dict[str, Any]], dict[str, Any] | str | None]


@dataclass(frozen=True)
class EndpointExtension:
    plugin_name: str
    path: str
    methods: tuple[str, ...]
    handler: EndpointHandler


@dataclass(frozen=True)
class TableExtension:
    plugin_name: str
    table_name: str


@dataclass(frozen=True)
class ColumnExtension:
    plugin_name: str
    table_name: str
    column_name: str


@dataclass(frozen=True)
class HookExecutionReport:
    hook: HookName
    tenant_id: str
    payload: dict[str, Any]
    executed_plugins: tuple[str, ...]
    errors: tuple[HookError, ...]


@dataclass(frozen=True)
class EndpointExecutionReport:
    tenant_id: str
    plugin_name: str
    path: str
    methods: tuple[str, ...]
    result: dict[str, Any] | str | None
    errors: tuple[HookError, ...]


@dataclass(frozen=True)
class PluginAuditRecord:
    tenant_id: str
    plugin_name: str
    target: str
    execution_type: Literal["hook", "endpoint", "lifecycle"]
    status: Literal["succeeded", "failed"]
    fail_closed: bool
    duration_ms: int
    error_classification: str | None = None
    message: str | None = None


class HookErrorClass(StrEnum):
    TIMEOUT = "timeout"
    VALIDATION = "validation"
    RUNTIME = "runtime"
    TRUST = "trust"


@dataclass(frozen=True)
class HookError:
    plugin_name: str
    classification: HookErrorClass
    message: str


class Plugin(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def order(self) -> int: ...

    def hooks(self) -> Mapping[HookName, HookHandler]: ...

    def register_endpoints(self) -> Sequence[EndpointExtension]: ...

    def register_tables(self) -> Sequence[TableExtension]: ...

    def register_columns(self) -> Sequence[ColumnExtension]: ...


class PluginExecutionError(RuntimeError):
    pass


@dataclass(frozen=True)
class PluginManifest:
    name: str
    version: str
    digest: str
    hooks: tuple[HookName, ...] = ()
    endpoints: tuple[str, ...] = ()
    requested_permissions: tuple[str, ...] = ()
    source_fingerprint: str | None = None
    signature: str | None = None
