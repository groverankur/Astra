from __future__ import annotations

import re
import sqlite3
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, cast
from urllib.parse import urlparse

_PLACEHOLDER_RE = re.compile(r"\{\{([a-zA-Z_][a-zA-Z0-9_]*)\}\}")
_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class DatabaseDialect(StrEnum):
    SQLITE = "sqlite"
    POSTGRES = "postgres"
    MYSQL = "mysql"


@dataclass(frozen=True)
class CompiledSQL:
    sql: str
    params: tuple[object, ...]


def sql_identifier(value: str) -> str:
    if not _IDENTIFIER_RE.fullmatch(value):
        raise ValueError(f"Invalid SQL identifier: {value}")
    return value


def _sql_identifiers(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(sql_identifier(value) for value in values)


class SyncCursor(Protocol):
    def fetchone(self) -> Mapping[str, Any] | None: ...
    def fetchall(self) -> Sequence[Mapping[str, Any]]: ...


class SyncConnection(Protocol):
    def __enter__(self) -> Any: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: object | None,
    ) -> object: ...

    def execute(self, sql: str, params: Sequence[object] = ()) -> SyncCursor: ...
    def commit(self) -> None: ...
    def close(self) -> None: ...


class _ManagedSyncConnection:
    def __enter__(self) -> _ManagedSyncConnection:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: object | None,
    ) -> object:
        return None


class _SQLiteSyncConnection(_ManagedSyncConnection):
    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def execute(self, sql: str, params: Sequence[object] = ()) -> SyncCursor:
        return cast(SyncCursor, self._connection.execute(sql, params))

    def commit(self) -> None:
        self._connection.commit()

    def close(self) -> None:
        self._connection.close()


class _PsycopgSyncConnection(_ManagedSyncConnection):
    def __init__(self, connection: Any) -> None:
        self._connection = connection

    def execute(self, sql: str, params: Sequence[object] = ()) -> SyncCursor:
        return cast(SyncCursor, self._connection.execute(sql, params))

    def commit(self) -> None:
        self._connection.commit()

    def close(self) -> None:
        self._connection.close()


class _PyMySQLSyncConnection(_ManagedSyncConnection):
    def __init__(self, connection: Any) -> None:
        self._connection = connection

    def execute(self, sql: str, params: Sequence[object] = ()) -> SyncCursor:
        cursor = self._connection.cursor()
        cursor.execute(sql, params)
        return cast(SyncCursor, cursor)

    def commit(self) -> None:
        self._connection.commit()

    def close(self) -> None:
        self._connection.close()


class AsyncCursor(Protocol):
    async def fetchone(self) -> Mapping[str, Any] | None: ...
    async def fetchall(self) -> Sequence[Mapping[str, Any]]: ...


class AsyncConnection(Protocol):
    async def execute(self, sql: str, params: Sequence[object] = ()) -> AsyncCursor: ...
    async def commit(self) -> None: ...
    async def close(self) -> None: ...


@dataclass
class RelationalDatabase:
    dsn: str
    dialect: DatabaseDialect
    _connect: Callable[[], SyncConnection]
    _connection: SyncConnection | None = field(default=None, init=False)

    def connection(self) -> SyncConnection:
        if self._connection is None:
            self._connection = self._connect()
        return self._connection

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None


@dataclass
class AsyncRelationalDatabase:
    dsn: str
    dialect: DatabaseDialect
    _connect: Callable[[], Awaitable[AsyncConnection]]
    _connection: AsyncConnection | None = field(default=None, init=False)

    async def connection(self) -> AsyncConnection:
        if self._connection is None:
            self._connection = await self._connect()
        return self._connection

    async def close(self) -> None:
        if self._connection is not None:
            await self._connection.close()
            self._connection = None


def normalize_sync_dsn(dsn: str) -> str:
    if "://" in dsn:
        return dsn
    if dsn == ":memory:":
        return "sqlite:///:memory:"
    return f"sqlite:///{Path(dsn).as_posix()}"


def normalize_async_dsn(dsn: str) -> str:
    if "://" in dsn:
        return dsn
    if dsn == ":memory:":
        return "sqlite+aiosqlite:///:memory:"
    return f"sqlite+aiosqlite:///{Path(dsn).as_posix()}"


def infer_dialect(dsn: str) -> DatabaseDialect:
    normalized = normalize_sync_dsn(dsn)
    parsed = urlparse(normalized)
    scheme = parsed.scheme.split("+", 1)[0]
    if scheme == "sqlite":
        return DatabaseDialect.SQLITE
    if scheme in {"postgres", "postgresql"}:
        return DatabaseDialect.POSTGRES
    if scheme == "mysql":
        return DatabaseDialect.MYSQL
    raise ValueError(f"Unsupported database scheme: {scheme}")


def compile_sql(
    template: str,
    params: Mapping[str, object] | None,
    dialect: DatabaseDialect,
) -> CompiledSQL:
    values: list[object] = []

    def repl(match: re.Match[str]) -> str:
        key = match.group(1)
        if params is None or key not in params:
            raise KeyError(f"Missing SQL parameter: {key}")
        values.append(params[key])
        if dialect == DatabaseDialect.SQLITE:
            return "?"
        return "%s"

    return CompiledSQL(sql=_PLACEHOLDER_RE.sub(repl, template), params=tuple(values))


def upsert_sql(
    *,
    table: str,
    columns: Sequence[str],
    conflict_columns: Sequence[str],
    dialect: DatabaseDialect,
) -> str:
    table_name = sql_identifier(table)
    column_names = _sql_identifiers(columns)
    conflict_column_names = _sql_identifiers(conflict_columns)
    insert_columns = ", ".join(column_names)
    values = ", ".join("{{" + column + "}}" for column in column_names)
    update_columns = [column for column in column_names if column not in conflict_column_names]
    insert_prefix = "INSERT " + "INTO " + table_name + f" ({insert_columns}) VALUES ({values}) "
    if dialect in {DatabaseDialect.SQLITE, DatabaseDialect.POSTGRES}:
        conflict_target = ", ".join(conflict_column_names)
        if not update_columns:
            return insert_prefix + "ON " + f"CONFLICT({conflict_target}) DO NOTHING"
        update_clause = ", ".join(f"{column}=excluded.{column}" for column in update_columns)
        return "".join(
            [
                insert_prefix,
                "ON ",
                "CONFLICT(",
                conflict_target,
                ") ",
                "DO ",
                "UPDATE ",
                "SET ",
                update_clause,
            ]
        )
    if not update_columns:
        identity_col = conflict_column_names[0]
        return insert_prefix + "ON " + f"DUPLICATE KEY UPDATE {identity_col}={identity_col}"
    update_clause = ", ".join(f"{column}=VALUES({column})" for column in update_columns)
    return insert_prefix + "ON " + "DUPLICATE KEY UPDATE " + update_clause


def _sqlite_path(normalized: str) -> str:
    parsed = urlparse(normalized)
    target = parsed.path if parsed.path else ":memory:"
    if target in {"/:memory:", ":memory:"}:
        return ":memory:"
    path = target.lstrip("/")
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    return path


def _create_sqlite_connection(normalized: str) -> SyncConnection:
    conn = sqlite3.connect(_sqlite_path(normalized))
    conn.row_factory = sqlite3.Row
    return _SQLiteSyncConnection(conn)


def _create_postgres_connection(normalized: str) -> SyncConnection:
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError as exc:
        raise RuntimeError("Install astraauth-core with the 'postgres' extra") from exc
    return _PsycopgSyncConnection(psycopg.connect(normalized, row_factory=cast(Any, dict_row)))


def _create_mysql_connection(normalized: str) -> SyncConnection:
    try:
        import pymysql
        from pymysql.cursors import DictCursor
    except ImportError as exc:
        raise RuntimeError("Install astraauth-core with the 'mysql' extra") from exc
    parsed = urlparse(normalized)
    return _PyMySQLSyncConnection(
        pymysql.connect(
            host=parsed.hostname,
            port=parsed.port or 3306,
            user=parsed.username,
            password=parsed.password,
            database=parsed.path.lstrip("/"),
            cursorclass=DictCursor,
            autocommit=False,
        )
    )


def create_sync_database(dsn: str) -> RelationalDatabase:
    normalized = normalize_sync_dsn(dsn)
    dialect = infer_dialect(normalized)
    connect_map: dict[DatabaseDialect, Callable[[], SyncConnection]] = {
        DatabaseDialect.SQLITE: lambda: _create_sqlite_connection(normalized),
        DatabaseDialect.POSTGRES: lambda: _create_postgres_connection(normalized),
        DatabaseDialect.MYSQL: lambda: _create_mysql_connection(normalized),
    }
    return RelationalDatabase(dsn=normalized, dialect=dialect, _connect=connect_map[dialect])


async def _create_async_sqlite_connection(normalized: str) -> AsyncConnection:
    try:
        import aiosqlite
    except ImportError as exc:
        raise RuntimeError("Install astraauth-core with the 'sql-async' extra") from exc
    conn = await aiosqlite.connect(_sqlite_path(normalized))
    conn.row_factory = aiosqlite.Row
    return cast(AsyncConnection, conn)


async def _create_async_postgres_connection(normalized: str) -> AsyncConnection:
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError as exc:
        raise RuntimeError("Install astraauth-core with the 'sql-async' extra") from exc
    return cast(
        AsyncConnection,
        await psycopg.AsyncConnection.connect(normalized, row_factory=cast(Any, dict_row)),
    )


async def _create_async_mysql_connection(normalized: str) -> AsyncConnection:
    try:
        import aiomysql
    except ImportError as exc:
        raise RuntimeError("Install astraauth-core with the 'sql-async' extra") from exc
    parsed = urlparse(normalized)
    return cast(
        AsyncConnection,
        await aiomysql.connect(
            host=parsed.hostname,
            port=parsed.port or 3306,
            user=parsed.username,
            password=parsed.password,
            db=parsed.path.lstrip("/"),
            autocommit=False,
        ),
    )


def create_async_database(dsn: str) -> AsyncRelationalDatabase:
    normalized = normalize_async_dsn(dsn)
    parsed = urlparse(normalized)
    scheme = parsed.scheme.split("+", 1)[0]
    scheme_map = {
        "sqlite": DatabaseDialect.SQLITE,
        "postgres": DatabaseDialect.POSTGRES,
        "postgresql": DatabaseDialect.POSTGRES,
        "mysql": DatabaseDialect.MYSQL,
    }
    if scheme not in scheme_map:
        raise ValueError(f"Unsupported database scheme: {scheme}")
    dialect = scheme_map[scheme]
    connect_map: dict[DatabaseDialect, Callable[[], Awaitable[AsyncConnection]]] = {
        DatabaseDialect.SQLITE: lambda: _create_async_sqlite_connection(normalized),
        DatabaseDialect.POSTGRES: lambda: _create_async_postgres_connection(normalized),
        DatabaseDialect.MYSQL: lambda: _create_async_mysql_connection(normalized),
    }
    return AsyncRelationalDatabase(dsn=normalized, dialect=dialect, _connect=connect_map[dialect])
