from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime

from astraauth_core.persistence import (
    AsyncRelationalDatabase,
    RelationalDatabase,
    compile_sql,
    create_async_database,
    create_sync_database,
    upsert_sql,
)
from astraauth_core.sessions.models import Session
from astraauth_core.sessions.store import BaseSessionStore

_SESSION_COLUMNS = (
    "session_id",
    "subject_id",
    "tenant_id",
    "client_id",
    "requested_scopes",
    "created_at",
    "expires_at",
    "revoked",
    "version",
    "acr",
    "amr",
    "authenticated_at",
    "upgraded_at",
)


def _row_int(row: dict[str, object], key: str) -> int:
    return int(str(row[key]))


def _row_to_session(row: dict[str, object]) -> Session:
    return Session(
        session_id=str(row["session_id"]),
        subject_id=str(row["subject_id"]),
        tenant_id=str(row["tenant_id"]),
        client_id=str(row["client_id"]),
        requested_scopes=set(json.loads(str(row["requested_scopes"]))),
        created_at=datetime.fromisoformat(str(row["created_at"])).replace(tzinfo=UTC),
        expires_at=datetime.fromisoformat(str(row["expires_at"])).replace(tzinfo=UTC),
        revoked=bool(row["revoked"]),
        version=_row_int(row, "version"),
        acr=_row_int(row, "acr"),
        amr=tuple(json.loads(str(row["amr"]))),
        authenticated_at=(
            datetime.fromisoformat(str(row["authenticated_at"])).replace(tzinfo=UTC)
            if row["authenticated_at"] is not None
            else None
        ),
        upgraded_at=(
            datetime.fromisoformat(str(row["upgraded_at"])).replace(tzinfo=UTC)
            if row["upgraded_at"] is not None
            else None
        ),
    )


def _session_params(session: Session) -> dict[str, object]:
    return {
        "session_id": session.session_id,
        "subject_id": session.subject_id,
        "tenant_id": session.tenant_id,
        "client_id": session.client_id,
        "requested_scopes": json.dumps(sorted(session.requested_scopes)),
        "created_at": session.created_at.isoformat(),
        "expires_at": session.expires_at.isoformat(),
        "revoked": 1 if session.revoked else 0,
        "version": session.version,
        "acr": session.acr,
        "amr": json.dumps(list(session.amr)),
        "authenticated_at": session.authenticated_at.isoformat() if session.authenticated_at else None,
        "upgraded_at": session.upgraded_at.isoformat() if session.upgraded_at else None,
    }


class SQLSessionStore(BaseSessionStore):
    def __init__(self, dsn: str = ":memory:", *, database: RelationalDatabase | None = None) -> None:
        self._database = database or create_sync_database(dsn)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        ddl = """
        CREATE TABLE IF NOT EXISTS auth_sessions (
            session_id TEXT PRIMARY KEY,
            subject_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            client_id TEXT NOT NULL,
            requested_scopes TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked INTEGER NOT NULL,
            version INTEGER NOT NULL,
            acr INTEGER NOT NULL,
            amr TEXT NOT NULL,
            authenticated_at TEXT NULL,
            upgraded_at TEXT NULL
        )
        """
        with self._database.connection() as conn:
            conn.execute(ddl)
            conn.commit()

    def save(self, session: Session) -> None:
        sql = upsert_sql(
            table="auth_sessions",
            columns=_SESSION_COLUMNS,
            conflict_columns=("session_id",),
            dialect=self._database.dialect,
        )
        compiled = compile_sql(sql, _session_params(session), self._database.dialect)
        with self._database.connection() as conn:
            conn.execute(compiled.sql, compiled.params)
            conn.commit()

    def get(self, session_id: str) -> Session | None:
        compiled = compile_sql(
            "SELECT * FROM auth_sessions WHERE session_id = {{session_id}}",
            {"session_id": session_id},
            self._database.dialect,
        )
        with self._database.connection() as conn:
            row = conn.execute(compiled.sql, compiled.params).fetchone()
            if row is None:
                return None
            return _row_to_session(dict(row))

    def revoke(self, session_id: str) -> None:
        compiled = compile_sql(
            "UPDATE auth_sessions SET revoked = {{revoked}} WHERE session_id = {{session_id}}",
            {"revoked": 1, "session_id": session_id},
            self._database.dialect,
        )
        with self._database.connection() as conn:
            conn.execute(compiled.sql, compiled.params)
            conn.commit()

    def _iter_sessions(self) -> Iterable[Session]:
        with self._database.connection() as conn:
            rows = conn.execute("SELECT * FROM auth_sessions").fetchall()
            return [_row_to_session(dict(row)) for row in rows]


class AsyncSQLSessionStore:
    def __init__(self, dsn: str = ":memory:", *, database: AsyncRelationalDatabase | None = None) -> None:
        self._database = database or create_async_database(dsn)

    async def close(self) -> None:
        await self._database.close()

    async def ensure_schema(self) -> None:
        ddl = """
        CREATE TABLE IF NOT EXISTS auth_sessions (
            session_id TEXT PRIMARY KEY,
            subject_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            client_id TEXT NOT NULL,
            requested_scopes TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked INTEGER NOT NULL,
            version INTEGER NOT NULL,
            acr INTEGER NOT NULL,
            amr TEXT NOT NULL,
            authenticated_at TEXT NULL,
            upgraded_at TEXT NULL
        )
        """
        conn = await self._database.connection()
        await conn.execute(ddl)
        await conn.commit()

    async def save(self, session: Session) -> None:
        sql = upsert_sql(
            table="auth_sessions",
            columns=_SESSION_COLUMNS,
            conflict_columns=("session_id",),
            dialect=self._database.dialect,
        )
        compiled = compile_sql(sql, _session_params(session), self._database.dialect)
        conn = await self._database.connection()
        await conn.execute(compiled.sql, compiled.params)
        await conn.commit()

    async def get(self, session_id: str) -> Session | None:
        compiled = compile_sql(
            "SELECT * FROM auth_sessions WHERE session_id = {{session_id}}",
            {"session_id": session_id},
            self._database.dialect,
        )
        conn = await self._database.connection()
        cursor = await conn.execute(compiled.sql, compiled.params)
        row = await cursor.fetchone()
        if row is None:
            return None
        return _row_to_session(dict(row))

    async def revoke(self, session_id: str) -> None:
        compiled = compile_sql(
            "UPDATE auth_sessions SET revoked = {{revoked}} WHERE session_id = {{session_id}}",
            {"revoked": 1, "session_id": session_id},
            self._database.dialect,
        )
        conn = await self._database.connection()
        await conn.execute(compiled.sql, compiled.params)
        await conn.commit()
