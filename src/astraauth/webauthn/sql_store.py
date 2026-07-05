from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from astraauth.core.persistence import (
    AsyncRelationalDatabase,
    RelationalDatabase,
    compile_sql,
    create_async_database,
    create_sync_database,
    upsert_sql,
)
from astraauth.webauthn.models import (
    WebAuthnAuthenticationState,
    WebAuthnCredential,
    WebAuthnRegistrationState,
)
from astraauth.webauthn.store import (
    BaseWebAuthnCredentialRepository,
    WebAuthnAuthenticationStateRepository,
    WebAuthnRegistrationStateRepository,
)

_CREDENTIAL_COLUMNS = (
    "credential_id",
    "subject_id",
    "tenant_id",
    "public_key",
    "sign_count",
    "transports",
    "created_at",
)
_REGISTRATION_STATE_COLUMNS = (
    "state_id",
    "session_id",
    "subject_id",
    "tenant_id",
    "challenge",
    "user_name",
    "created_at",
    "expires_at",
)
_AUTHENTICATION_STATE_COLUMNS = (
    "state_id",
    "mfa_challenge_id",
    "session_id",
    "subject_id",
    "tenant_id",
    "challenge",
    "created_at",
    "expires_at",
)


def _credential_params(credential: WebAuthnCredential) -> dict[str, object]:
    return {
        "credential_id": credential.credential_id,
        "subject_id": credential.subject_id,
        "tenant_id": credential.tenant_id,
        "public_key": credential.public_key,
        "sign_count": credential.sign_count,
        "transports": ",".join(credential.transports),
        "created_at": credential.created_at.isoformat(),
    }


def _credential_from_row(row: dict[str, object]) -> WebAuthnCredential:
    transports = str(row["transports"]).split(",") if row["transports"] else []
    return WebAuthnCredential(
        credential_id=str(row["credential_id"]),
        subject_id=str(row["subject_id"]),
        tenant_id=str(row["tenant_id"]),
        public_key=str(row["public_key"]),
        sign_count=int(str(row["sign_count"])),
        transports=tuple(filter(None, transports)),
        created_at=datetime.fromisoformat(str(row["created_at"])).replace(tzinfo=UTC),
    )


def _registration_state_params(state: WebAuthnRegistrationState) -> dict[str, object]:
    return {
        "state_id": state.state_id,
        "session_id": state.session_id,
        "subject_id": state.subject_id,
        "tenant_id": state.tenant_id,
        "challenge": state.challenge,
        "user_name": state.user_name,
        "created_at": state.created_at.isoformat(),
        "expires_at": state.expires_at.isoformat(),
    }


def _registration_state_from_row(row: dict[str, object]) -> WebAuthnRegistrationState:
    return WebAuthnRegistrationState(
        state_id=str(row["state_id"]),
        session_id=str(row["session_id"]),
        subject_id=str(row["subject_id"]),
        tenant_id=str(row["tenant_id"]),
        challenge=str(row["challenge"]),
        user_name=str(row["user_name"]),
        created_at=datetime.fromisoformat(str(row["created_at"])).replace(tzinfo=UTC),
        expires_at=datetime.fromisoformat(str(row["expires_at"])).replace(tzinfo=UTC),
    )


def _authentication_state_params(state: WebAuthnAuthenticationState) -> dict[str, object]:
    return {
        "state_id": state.state_id,
        "mfa_challenge_id": state.mfa_challenge_id,
        "session_id": state.session_id,
        "subject_id": state.subject_id,
        "tenant_id": state.tenant_id,
        "challenge": state.challenge,
        "created_at": state.created_at.isoformat(),
        "expires_at": state.expires_at.isoformat(),
    }


def _authentication_state_from_row(row: dict[str, object]) -> WebAuthnAuthenticationState:
    return WebAuthnAuthenticationState(
        state_id=str(row["state_id"]),
        mfa_challenge_id=str(row["mfa_challenge_id"]),
        session_id=str(row["session_id"]),
        subject_id=str(row["subject_id"]),
        tenant_id=str(row["tenant_id"]),
        challenge=str(row["challenge"]),
        created_at=datetime.fromisoformat(str(row["created_at"])).replace(tzinfo=UTC),
        expires_at=datetime.fromisoformat(str(row["expires_at"])).replace(tzinfo=UTC),
    )


class SQLWebAuthnCredentialRepository(BaseWebAuthnCredentialRepository):
    def __init__(
        self, dsn: str = ":memory:", *, database: RelationalDatabase | None = None
    ) -> None:
        self._database = database or create_sync_database(dsn)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        ddl = """
        CREATE TABLE IF NOT EXISTS webauthn_credentials (
            credential_id VARCHAR(255) PRIMARY KEY,
            subject_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            public_key TEXT NOT NULL,
            sign_count INTEGER NOT NULL,
            transports TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
        with self._database.connection() as conn:
            conn.execute(ddl)
            conn.commit()

    def save(self, credential: WebAuthnCredential) -> None:
        sql = upsert_sql(
            table="webauthn_credentials",
            columns=_CREDENTIAL_COLUMNS,
            conflict_columns=("credential_id",),
            dialect=self._database.dialect,
        )
        compiled = compile_sql(sql, _credential_params(credential), self._database.dialect)
        with self._database.connection() as conn:
            conn.execute(compiled.sql, compiled.params)
            conn.commit()

    def get(self, credential_id: str) -> WebAuthnCredential | None:
        compiled = compile_sql(
            "SELECT * FROM webauthn_credentials WHERE credential_id = {{credential_id}}",
            {"credential_id": credential_id},
            self._database.dialect,
        )
        with self._database.connection() as conn:
            row = conn.execute(compiled.sql, compiled.params).fetchone()
            return _credential_from_row(dict(row)) if row is not None else None

    def _iter_credentials(self) -> Iterable[WebAuthnCredential]:
        with self._database.connection() as conn:
            rows = conn.execute("SELECT * FROM webauthn_credentials").fetchall()
            return [_credential_from_row(dict(row)) for row in rows]


class SQLWebAuthnRegistrationStateRepository(WebAuthnRegistrationStateRepository):
    def __init__(
        self, dsn: str = ":memory:", *, database: RelationalDatabase | None = None
    ) -> None:
        self._database = database or create_sync_database(dsn)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        ddl = """
        CREATE TABLE IF NOT EXISTS webauthn_registration_states (
            state_id VARCHAR(255) PRIMARY KEY,
            session_id TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            challenge TEXT NOT NULL,
            user_name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
        """
        with self._database.connection() as conn:
            conn.execute(ddl)
            conn.commit()

    def save(self, state: WebAuthnRegistrationState) -> None:
        sql = upsert_sql(
            table="webauthn_registration_states",
            columns=_REGISTRATION_STATE_COLUMNS,
            conflict_columns=("state_id",),
            dialect=self._database.dialect,
        )
        compiled = compile_sql(sql, _registration_state_params(state), self._database.dialect)
        with self._database.connection() as conn:
            conn.execute(compiled.sql, compiled.params)
            conn.commit()

    def get(self, state_id: str) -> WebAuthnRegistrationState | None:
        compiled = compile_sql(
            "SELECT * FROM webauthn_registration_states WHERE state_id = {{state_id}}",
            {"state_id": state_id},
            self._database.dialect,
        )
        with self._database.connection() as conn:
            row = conn.execute(compiled.sql, compiled.params).fetchone()
            return _registration_state_from_row(dict(row)) if row is not None else None

    def delete(self, state_id: str) -> None:
        compiled = compile_sql(
            "DELETE FROM webauthn_registration_states WHERE state_id = {{state_id}}",
            {"state_id": state_id},
            self._database.dialect,
        )
        with self._database.connection() as conn:
            conn.execute(compiled.sql, compiled.params)
            conn.commit()


class SQLWebAuthnAuthenticationStateRepository(WebAuthnAuthenticationStateRepository):
    def __init__(
        self, dsn: str = ":memory:", *, database: RelationalDatabase | None = None
    ) -> None:
        self._database = database or create_sync_database(dsn)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        ddl = """
        CREATE TABLE IF NOT EXISTS webauthn_authentication_states (
            state_id VARCHAR(255) PRIMARY KEY,
            mfa_challenge_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            challenge TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
        """
        with self._database.connection() as conn:
            conn.execute(ddl)
            conn.commit()

    def save(self, state: WebAuthnAuthenticationState) -> None:
        sql = upsert_sql(
            table="webauthn_authentication_states",
            columns=_AUTHENTICATION_STATE_COLUMNS,
            conflict_columns=("state_id",),
            dialect=self._database.dialect,
        )
        compiled = compile_sql(sql, _authentication_state_params(state), self._database.dialect)
        with self._database.connection() as conn:
            conn.execute(compiled.sql, compiled.params)
            conn.commit()

    def get(self, state_id: str) -> WebAuthnAuthenticationState | None:
        compiled = compile_sql(
            "SELECT * FROM webauthn_authentication_states WHERE state_id = {{state_id}}",
            {"state_id": state_id},
            self._database.dialect,
        )
        with self._database.connection() as conn:
            row = conn.execute(compiled.sql, compiled.params).fetchone()
            return _authentication_state_from_row(dict(row)) if row is not None else None

    def delete(self, state_id: str) -> None:
        compiled = compile_sql(
            "DELETE FROM webauthn_authentication_states WHERE state_id = {{state_id}}",
            {"state_id": state_id},
            self._database.dialect,
        )
        with self._database.connection() as conn:
            conn.execute(compiled.sql, compiled.params)
            conn.commit()


class AsyncSQLWebAuthnCredentialRepository:
    def __init__(
        self, dsn: str = ":memory:", *, database: AsyncRelationalDatabase | None = None
    ) -> None:
        self._database = database or create_async_database(dsn)

    async def ensure_schema(self) -> None:
        conn = await self._database.connection()
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS webauthn_credentials (
                credential_id VARCHAR(255) PRIMARY KEY,
                subject_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                public_key TEXT NOT NULL,
                sign_count INTEGER NOT NULL,
                transports TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        await conn.commit()

    async def save(self, credential: WebAuthnCredential) -> None:
        sql = upsert_sql(
            table="webauthn_credentials",
            columns=_CREDENTIAL_COLUMNS,
            conflict_columns=("credential_id",),
            dialect=self._database.dialect,
        )
        compiled = compile_sql(sql, _credential_params(credential), self._database.dialect)
        conn = await self._database.connection()
        await conn.execute(compiled.sql, compiled.params)
        await conn.commit()

    async def get(self, credential_id: str) -> WebAuthnCredential | None:
        compiled = compile_sql(
            "SELECT * FROM webauthn_credentials WHERE credential_id = {{credential_id}}",
            {"credential_id": credential_id},
            self._database.dialect,
        )
        conn = await self._database.connection()
        cursor = await conn.execute(compiled.sql, compiled.params)
        row = await cursor.fetchone()
        return _credential_from_row(dict(row)) if row is not None else None


class AsyncSQLWebAuthnRegistrationStateRepository:
    def __init__(
        self, dsn: str = ":memory:", *, database: AsyncRelationalDatabase | None = None
    ) -> None:
        self._database = database or create_async_database(dsn)

    async def ensure_schema(self) -> None:
        conn = await self._database.connection()
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS webauthn_registration_states (
                state_id VARCHAR(255) PRIMARY KEY,
                session_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                challenge TEXT NOT NULL,
                user_name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
            """
        )
        await conn.commit()

    async def save(self, state: WebAuthnRegistrationState) -> None:
        sql = upsert_sql(
            table="webauthn_registration_states",
            columns=_REGISTRATION_STATE_COLUMNS,
            conflict_columns=("state_id",),
            dialect=self._database.dialect,
        )
        compiled = compile_sql(sql, _registration_state_params(state), self._database.dialect)
        conn = await self._database.connection()
        await conn.execute(compiled.sql, compiled.params)
        await conn.commit()

    async def get(self, state_id: str) -> WebAuthnRegistrationState | None:
        compiled = compile_sql(
            "SELECT * FROM webauthn_registration_states WHERE state_id = {{state_id}}",
            {"state_id": state_id},
            self._database.dialect,
        )
        conn = await self._database.connection()
        cursor = await conn.execute(compiled.sql, compiled.params)
        row = await cursor.fetchone()
        return _registration_state_from_row(dict(row)) if row is not None else None

    async def delete(self, state_id: str) -> None:
        compiled = compile_sql(
            "DELETE FROM webauthn_registration_states WHERE state_id = {{state_id}}",
            {"state_id": state_id},
            self._database.dialect,
        )
        conn = await self._database.connection()
        await conn.execute(compiled.sql, compiled.params)
        await conn.commit()


class AsyncSQLWebAuthnAuthenticationStateRepository:
    def __init__(
        self, dsn: str = ":memory:", *, database: AsyncRelationalDatabase | None = None
    ) -> None:
        self._database = database or create_async_database(dsn)

    async def ensure_schema(self) -> None:
        conn = await self._database.connection()
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS webauthn_authentication_states (
                state_id VARCHAR(255) PRIMARY KEY,
                mfa_challenge_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                challenge TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
            """
        )
        await conn.commit()

    async def save(self, state: WebAuthnAuthenticationState) -> None:
        sql = upsert_sql(
            table="webauthn_authentication_states",
            columns=_AUTHENTICATION_STATE_COLUMNS,
            conflict_columns=("state_id",),
            dialect=self._database.dialect,
        )
        compiled = compile_sql(sql, _authentication_state_params(state), self._database.dialect)
        conn = await self._database.connection()
        await conn.execute(compiled.sql, compiled.params)
        await conn.commit()

    async def get(self, state_id: str) -> WebAuthnAuthenticationState | None:
        compiled = compile_sql(
            "SELECT * FROM webauthn_authentication_states WHERE state_id = {{state_id}}",
            {"state_id": state_id},
            self._database.dialect,
        )
        conn = await self._database.connection()
        cursor = await conn.execute(compiled.sql, compiled.params)
        row = await cursor.fetchone()
        return _authentication_state_from_row(dict(row)) if row is not None else None

    async def delete(self, state_id: str) -> None:
        compiled = compile_sql(
            "DELETE FROM webauthn_authentication_states WHERE state_id = {{state_id}}",
            {"state_id": state_id},
            self._database.dialect,
        )
        conn = await self._database.connection()
        await conn.execute(compiled.sql, compiled.params)
        await conn.commit()
