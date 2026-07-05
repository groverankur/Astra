from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from astraauth.core.mfa.models import (
    EmailOTPCode,
    EmailOTPFactor,
    MFAChallenge,
    MFAChallengeStatus,
    MFAFactorType,
    TOTPFactor,
)
from astraauth.core.mfa.store import (
    BaseEmailOTPCodeStore,
    BaseEmailOTPFactorStore,
    BaseMFAChallengeStore,
    BaseTOTPFactorStore,
)
from astraauth.core.persistence import (
    AsyncRelationalDatabase,
    RelationalDatabase,
    compile_sql,
    create_async_database,
    create_sync_database,
    upsert_sql,
)

_MFA_CHALLENGE_COLUMNS = (
    "challenge_id",
    "session_id",
    "subject_id",
    "tenant_id",
    "factor_type",
    "required_acr",
    "purpose",
    "created_at",
    "expires_at",
    "status",
    "verified_at",
)
_TOTP_COLUMNS = (
    "factor_id",
    "subject_id",
    "tenant_id",
    "secret",
    "issuer",
    "account_name",
    "digits",
    "period",
    "algorithm",
    "created_at",
    "enabled",
    "verified_at",
)
_EMAIL_FACTOR_COLUMNS = (
    "factor_id",
    "subject_id",
    "tenant_id",
    "email",
    "issuer",
    "created_at",
    "enabled",
    "verified_at",
)
_EMAIL_CODE_COLUMNS = (
    "challenge_id",
    "factor_id",
    "code",
    "created_at",
    "expires_at",
    "consumed_at",
)


def _challenge_params(challenge: MFAChallenge) -> dict[str, object]:
    return {
        "challenge_id": challenge.challenge_id,
        "session_id": challenge.session_id,
        "subject_id": challenge.subject_id,
        "tenant_id": challenge.tenant_id,
        "factor_type": challenge.factor_type.value,
        "required_acr": challenge.required_acr,
        "purpose": challenge.purpose,
        "created_at": challenge.created_at.isoformat(),
        "expires_at": challenge.expires_at.isoformat(),
        "status": challenge.status.value,
        "verified_at": challenge.verified_at.isoformat() if challenge.verified_at else None,
    }


def _challenge_from_row(row: dict[str, object]) -> MFAChallenge:
    return MFAChallenge(
        challenge_id=str(row["challenge_id"]),
        session_id=str(row["session_id"]),
        subject_id=str(row["subject_id"]),
        tenant_id=str(row["tenant_id"]),
        factor_type=MFAFactorType(str(row["factor_type"])),
        required_acr=int(str(row["required_acr"])),
        purpose=str(row["purpose"]),
        created_at=datetime.fromisoformat(str(row["created_at"])).replace(tzinfo=UTC),
        expires_at=datetime.fromisoformat(str(row["expires_at"])).replace(tzinfo=UTC),
        status=MFAChallengeStatus(str(row["status"])),
        verified_at=(
            datetime.fromisoformat(str(row["verified_at"])).replace(tzinfo=UTC)
            if row["verified_at"]
            else None
        ),
    )


def _totp_params(factor: TOTPFactor) -> dict[str, object]:
    return {
        "factor_id": factor.factor_id,
        "subject_id": factor.subject_id,
        "tenant_id": factor.tenant_id,
        "secret": factor.secret,
        "issuer": factor.issuer,
        "account_name": factor.account_name,
        "digits": factor.digits,
        "period": factor.period,
        "algorithm": factor.algorithm,
        "created_at": factor.created_at.isoformat(),
        "enabled": 1 if factor.enabled else 0,
        "verified_at": factor.verified_at.isoformat() if factor.verified_at else None,
    }


def _totp_from_row(row: dict[str, object]) -> TOTPFactor:
    return TOTPFactor(
        factor_id=str(row["factor_id"]),
        subject_id=str(row["subject_id"]),
        tenant_id=str(row["tenant_id"]),
        secret=str(row["secret"]),
        issuer=str(row["issuer"]),
        account_name=str(row["account_name"]),
        digits=int(str(row["digits"])),
        period=int(str(row["period"])),
        algorithm=str(row["algorithm"]),
        created_at=datetime.fromisoformat(str(row["created_at"])).replace(tzinfo=UTC),
        enabled=bool(row["enabled"]),
        verified_at=(
            datetime.fromisoformat(str(row["verified_at"])).replace(tzinfo=UTC)
            if row["verified_at"]
            else None
        ),
    )


def _email_factor_params(factor: EmailOTPFactor) -> dict[str, object]:
    return {
        "factor_id": factor.factor_id,
        "subject_id": factor.subject_id,
        "tenant_id": factor.tenant_id,
        "email": factor.email,
        "issuer": factor.issuer,
        "created_at": factor.created_at.isoformat(),
        "enabled": 1 if factor.enabled else 0,
        "verified_at": factor.verified_at.isoformat() if factor.verified_at else None,
    }


def _email_factor_from_row(row: dict[str, object]) -> EmailOTPFactor:
    return EmailOTPFactor(
        factor_id=str(row["factor_id"]),
        subject_id=str(row["subject_id"]),
        tenant_id=str(row["tenant_id"]),
        email=str(row["email"]),
        issuer=str(row["issuer"]),
        created_at=datetime.fromisoformat(str(row["created_at"])).replace(tzinfo=UTC),
        enabled=bool(row["enabled"]),
        verified_at=(
            datetime.fromisoformat(str(row["verified_at"])).replace(tzinfo=UTC)
            if row["verified_at"]
            else None
        ),
    )


def _email_code_params(code: EmailOTPCode) -> dict[str, object]:
    return {
        "challenge_id": code.challenge_id,
        "factor_id": code.factor_id,
        "code": code.code,
        "created_at": code.created_at.isoformat(),
        "expires_at": code.expires_at.isoformat(),
        "consumed_at": code.consumed_at.isoformat() if code.consumed_at else None,
    }


def _email_code_from_row(row: dict[str, object]) -> EmailOTPCode:
    return EmailOTPCode(
        challenge_id=str(row["challenge_id"]),
        factor_id=str(row["factor_id"]),
        code=str(row["code"]),
        created_at=datetime.fromisoformat(str(row["created_at"])).replace(tzinfo=UTC),
        expires_at=datetime.fromisoformat(str(row["expires_at"])).replace(tzinfo=UTC),
        consumed_at=(
            datetime.fromisoformat(str(row["consumed_at"])).replace(tzinfo=UTC)
            if row["consumed_at"]
            else None
        ),
    )


class SQLMFAChallengeStore(BaseMFAChallengeStore):
    def __init__(
        self, dsn: str = ":memory:", *, database: RelationalDatabase | None = None
    ) -> None:
        self._database = database or create_sync_database(dsn)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        ddl = """
        CREATE TABLE IF NOT EXISTS mfa_challenges (
            challenge_id VARCHAR(255) PRIMARY KEY,
            session_id TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            factor_type TEXT NOT NULL,
            required_acr INTEGER NOT NULL,
            purpose TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            status TEXT NOT NULL,
            verified_at TEXT NULL
        )
        """
        with self._database.connection() as conn:
            conn.execute(ddl)
            conn.commit()

    def save(self, challenge: MFAChallenge) -> None:
        sql = upsert_sql(
            table="mfa_challenges",
            columns=_MFA_CHALLENGE_COLUMNS,
            conflict_columns=("challenge_id",),
            dialect=self._database.dialect,
        )
        compiled = compile_sql(sql, _challenge_params(challenge), self._database.dialect)
        with self._database.connection() as conn:
            conn.execute(compiled.sql, compiled.params)
            conn.commit()

    def get(self, challenge_id: str) -> MFAChallenge | None:
        compiled = compile_sql(
            "SELECT * FROM mfa_challenges WHERE challenge_id = {{challenge_id}}",
            {"challenge_id": challenge_id},
            self._database.dialect,
        )
        with self._database.connection() as conn:
            row = conn.execute(compiled.sql, compiled.params).fetchone()
            return _challenge_from_row(dict(row)) if row is not None else None

    def _iter_challenges(self) -> Iterable[MFAChallenge]:
        with self._database.connection() as conn:
            rows = conn.execute("SELECT * FROM mfa_challenges").fetchall()
            return [_challenge_from_row(dict(row)) for row in rows]


class SQLTOTPFactorStore(BaseTOTPFactorStore):
    def __init__(
        self, dsn: str = ":memory:", *, database: RelationalDatabase | None = None
    ) -> None:
        self._database = database or create_sync_database(dsn)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        ddl = """
        CREATE TABLE IF NOT EXISTS totp_factors (
            factor_id VARCHAR(255) PRIMARY KEY,
            subject_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            secret TEXT NOT NULL,
            issuer TEXT NOT NULL,
            account_name TEXT NOT NULL,
            digits INTEGER NOT NULL,
            period INTEGER NOT NULL,
            algorithm TEXT NOT NULL,
            created_at TEXT NOT NULL,
            enabled INTEGER NOT NULL,
            verified_at TEXT NULL
        )
        """
        with self._database.connection() as conn:
            conn.execute(ddl)
            conn.commit()

    def save(self, factor: TOTPFactor) -> None:
        sql = upsert_sql(
            table="totp_factors",
            columns=_TOTP_COLUMNS,
            conflict_columns=("factor_id",),
            dialect=self._database.dialect,
        )
        compiled = compile_sql(sql, _totp_params(factor), self._database.dialect)
        with self._database.connection() as conn:
            conn.execute(compiled.sql, compiled.params)
            conn.commit()

    def get(self, factor_id: str) -> TOTPFactor | None:
        compiled = compile_sql(
            "SELECT * FROM totp_factors WHERE factor_id = {{factor_id}}",
            {"factor_id": factor_id},
            self._database.dialect,
        )
        with self._database.connection() as conn:
            row = conn.execute(compiled.sql, compiled.params).fetchone()
            return _totp_from_row(dict(row)) if row is not None else None

    def _iter_factors(self) -> Iterable[TOTPFactor]:
        with self._database.connection() as conn:
            rows = conn.execute("SELECT * FROM totp_factors").fetchall()
            return [_totp_from_row(dict(row)) for row in rows]


class SQLEmailOTPFactorStore(BaseEmailOTPFactorStore):
    def __init__(
        self, dsn: str = ":memory:", *, database: RelationalDatabase | None = None
    ) -> None:
        self._database = database or create_sync_database(dsn)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        ddl = """
        CREATE TABLE IF NOT EXISTS email_otp_factors (
            factor_id VARCHAR(255) PRIMARY KEY,
            subject_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            email TEXT NOT NULL,
            issuer TEXT NOT NULL,
            created_at TEXT NOT NULL,
            enabled INTEGER NOT NULL,
            verified_at TEXT NULL
        )
        """
        with self._database.connection() as conn:
            conn.execute(ddl)
            conn.commit()

    def save(self, factor: EmailOTPFactor) -> None:
        sql = upsert_sql(
            table="email_otp_factors",
            columns=_EMAIL_FACTOR_COLUMNS,
            conflict_columns=("factor_id",),
            dialect=self._database.dialect,
        )
        compiled = compile_sql(sql, _email_factor_params(factor), self._database.dialect)
        with self._database.connection() as conn:
            conn.execute(compiled.sql, compiled.params)
            conn.commit()

    def get(self, factor_id: str) -> EmailOTPFactor | None:
        compiled = compile_sql(
            "SELECT * FROM email_otp_factors WHERE factor_id = {{factor_id}}",
            {"factor_id": factor_id},
            self._database.dialect,
        )
        with self._database.connection() as conn:
            row = conn.execute(compiled.sql, compiled.params).fetchone()
            return _email_factor_from_row(dict(row)) if row is not None else None

    def _iter_factors(self) -> Iterable[EmailOTPFactor]:
        with self._database.connection() as conn:
            rows = conn.execute("SELECT * FROM email_otp_factors").fetchall()
            return [_email_factor_from_row(dict(row)) for row in rows]


class SQLEmailOTPCodeStore(BaseEmailOTPCodeStore):
    def __init__(
        self, dsn: str = ":memory:", *, database: RelationalDatabase | None = None
    ) -> None:
        self._database = database or create_sync_database(dsn)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        ddl = """
        CREATE TABLE IF NOT EXISTS email_otp_codes (
            challenge_id TEXT PRIMARY KEY,
            factor_id TEXT NOT NULL,
            code TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            consumed_at TEXT NULL
        )
        """
        with self._database.connection() as conn:
            conn.execute(ddl)
            conn.commit()

    def save(self, code: EmailOTPCode) -> None:
        sql = upsert_sql(
            table="email_otp_codes",
            columns=_EMAIL_CODE_COLUMNS,
            conflict_columns=("challenge_id",),
            dialect=self._database.dialect,
        )
        compiled = compile_sql(sql, _email_code_params(code), self._database.dialect)
        with self._database.connection() as conn:
            conn.execute(compiled.sql, compiled.params)
            conn.commit()

    def get(self, challenge_id: str) -> EmailOTPCode | None:
        compiled = compile_sql(
            "SELECT * FROM email_otp_codes WHERE challenge_id = {{challenge_id}}",
            {"challenge_id": challenge_id},
            self._database.dialect,
        )
        with self._database.connection() as conn:
            row = conn.execute(compiled.sql, compiled.params).fetchone()
            return _email_code_from_row(dict(row)) if row is not None else None


class AsyncSQLMFAChallengeStore:
    def __init__(
        self, dsn: str = ":memory:", *, database: AsyncRelationalDatabase | None = None
    ) -> None:
        self._database = database or create_async_database(dsn)

    async def close(self) -> None:
        await self._database.close()

    async def ensure_schema(self) -> None:
        conn = await self._database.connection()
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mfa_challenges (
                challenge_id VARCHAR(255) PRIMARY KEY,
                session_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                factor_type TEXT NOT NULL,
                required_acr INTEGER NOT NULL,
                purpose TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                status TEXT NOT NULL,
                verified_at TEXT NULL
            )
            """
        )
        await conn.commit()

    async def save(self, challenge: MFAChallenge) -> None:
        sql = upsert_sql(
            table="mfa_challenges",
            columns=_MFA_CHALLENGE_COLUMNS,
            conflict_columns=("challenge_id",),
            dialect=self._database.dialect,
        )
        compiled = compile_sql(sql, _challenge_params(challenge), self._database.dialect)
        conn = await self._database.connection()
        await conn.execute(compiled.sql, compiled.params)
        await conn.commit()

    async def get(self, challenge_id: str) -> MFAChallenge | None:
        compiled = compile_sql(
            "SELECT * FROM mfa_challenges WHERE challenge_id = {{challenge_id}}",
            {"challenge_id": challenge_id},
            self._database.dialect,
        )
        conn = await self._database.connection()
        cursor = await conn.execute(compiled.sql, compiled.params)
        row = await cursor.fetchone()
        return _challenge_from_row(dict(row)) if row is not None else None


class AsyncSQLTOTPFactorStore:
    def __init__(
        self, dsn: str = ":memory:", *, database: AsyncRelationalDatabase | None = None
    ) -> None:
        self._database = database or create_async_database(dsn)

    async def close(self) -> None:
        await self._database.close()

    async def ensure_schema(self) -> None:
        conn = await self._database.connection()
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS totp_factors (
                factor_id VARCHAR(255) PRIMARY KEY,
                subject_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                secret TEXT NOT NULL,
                issuer TEXT NOT NULL,
                account_name TEXT NOT NULL,
                digits INTEGER NOT NULL,
                period INTEGER NOT NULL,
                algorithm TEXT NOT NULL,
                created_at TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                verified_at TEXT NULL
            )
            """
        )
        await conn.commit()

    async def save(self, factor: TOTPFactor) -> None:
        sql = upsert_sql(
            table="totp_factors",
            columns=_TOTP_COLUMNS,
            conflict_columns=("factor_id",),
            dialect=self._database.dialect,
        )
        compiled = compile_sql(sql, _totp_params(factor), self._database.dialect)
        conn = await self._database.connection()
        await conn.execute(compiled.sql, compiled.params)
        await conn.commit()

    async def get(self, factor_id: str) -> TOTPFactor | None:
        compiled = compile_sql(
            "SELECT * FROM totp_factors WHERE factor_id = {{factor_id}}",
            {"factor_id": factor_id},
            self._database.dialect,
        )
        conn = await self._database.connection()
        cursor = await conn.execute(compiled.sql, compiled.params)
        row = await cursor.fetchone()
        return _totp_from_row(dict(row)) if row is not None else None


class AsyncSQLEmailOTPFactorStore:
    def __init__(
        self, dsn: str = ":memory:", *, database: AsyncRelationalDatabase | None = None
    ) -> None:
        self._database = database or create_async_database(dsn)

    async def close(self) -> None:
        await self._database.close()

    async def ensure_schema(self) -> None:
        conn = await self._database.connection()
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS email_otp_factors (
                factor_id VARCHAR(255) PRIMARY KEY,
                subject_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                email TEXT NOT NULL,
                issuer TEXT NOT NULL,
                created_at TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                verified_at TEXT NULL
            )
            """
        )
        await conn.commit()

    async def save(self, factor: EmailOTPFactor) -> None:
        sql = upsert_sql(
            table="email_otp_factors",
            columns=_EMAIL_FACTOR_COLUMNS,
            conflict_columns=("factor_id",),
            dialect=self._database.dialect,
        )
        compiled = compile_sql(sql, _email_factor_params(factor), self._database.dialect)
        conn = await self._database.connection()
        await conn.execute(compiled.sql, compiled.params)
        await conn.commit()

    async def get(self, factor_id: str) -> EmailOTPFactor | None:
        compiled = compile_sql(
            "SELECT * FROM email_otp_factors WHERE factor_id = {{factor_id}}",
            {"factor_id": factor_id},
            self._database.dialect,
        )
        conn = await self._database.connection()
        cursor = await conn.execute(compiled.sql, compiled.params)
        row = await cursor.fetchone()
        return _email_factor_from_row(dict(row)) if row is not None else None


class AsyncSQLEmailOTPCodeStore:
    def __init__(
        self, dsn: str = ":memory:", *, database: AsyncRelationalDatabase | None = None
    ) -> None:
        self._database = database or create_async_database(dsn)

    async def close(self) -> None:
        await self._database.close()

    async def ensure_schema(self) -> None:
        conn = await self._database.connection()
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS email_otp_codes (
                challenge_id TEXT PRIMARY KEY,
                factor_id TEXT NOT NULL,
                code TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                consumed_at TEXT NULL
            )
            """
        )
        await conn.commit()

    async def save(self, code: EmailOTPCode) -> None:
        sql = upsert_sql(
            table="email_otp_codes",
            columns=_EMAIL_CODE_COLUMNS,
            conflict_columns=("challenge_id",),
            dialect=self._database.dialect,
        )
        compiled = compile_sql(sql, _email_code_params(code), self._database.dialect)
        conn = await self._database.connection()
        await conn.execute(compiled.sql, compiled.params)
        await conn.commit()

    async def get(self, challenge_id: str) -> EmailOTPCode | None:
        compiled = compile_sql(
            "SELECT * FROM email_otp_codes WHERE challenge_id = {{challenge_id}}",
            {"challenge_id": challenge_id},
            self._database.dialect,
        )
        conn = await self._database.connection()
        cursor = await conn.execute(compiled.sql, compiled.params)
        row = await cursor.fetchone()
        return _email_code_from_row(dict(row)) if row is not None else None
