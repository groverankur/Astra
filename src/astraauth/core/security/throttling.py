from __future__ import annotations

import json
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Protocol

from astraauth.core.persistence.relational import (
    DatabaseDialect,
    compile_sql,
    create_sync_database,
    infer_dialect,
    sql_identifier,
    upsert_sql,
)


class ThrottleStore(Protocol):
    def retry_after(
        self, *, bucket: str, window_seconds: float, now: float | None = None
    ) -> int: ...

    def record(
        self,
        *,
        bucket: str,
        max_events: int,
        window_seconds: float,
        block_seconds: float,
        now: float | None = None,
    ) -> int: ...

    def reset(self, *, bucket: str) -> None: ...

    def snapshot(self, *, now: float | None = None) -> ThrottleStoreSnapshot: ...


@dataclass(frozen=True)
class ThrottleBucketSnapshot:
    scope: str
    fingerprint: str
    event_count: int
    blocked: bool
    retry_after_seconds: int


@dataclass(frozen=True)
class ThrottleStoreSnapshot:
    storage_kind: str
    bucket_count: int
    blocked_bucket_count: int
    buckets: tuple[ThrottleBucketSnapshot, ...]
    dsn: str | None = None
    table_name: str | None = None


@dataclass
class _BucketState:
    timestamps: list[float] = field(default_factory=list)
    blocked_until: float = 0.0


class InMemoryThrottleStore:
    def __init__(self) -> None:
        self._buckets: dict[str, _BucketState] = {}

    def retry_after(self, *, bucket: str, window_seconds: float, now: float | None = None) -> int:
        current = now if now is not None else time.monotonic()
        state = self._bucket(bucket=bucket, now=current, window_seconds=window_seconds)
        if state.blocked_until > current:
            return max(1, int(state.blocked_until - current))
        return 0

    def record(
        self,
        *,
        bucket: str,
        max_events: int,
        window_seconds: float,
        block_seconds: float,
        now: float | None = None,
    ) -> int:
        current = now if now is not None else time.monotonic()
        state = self._bucket(bucket=bucket, now=current, window_seconds=window_seconds)
        if state.blocked_until > current:
            return max(1, int(state.blocked_until - current))
        state.timestamps.append(current)
        if len(state.timestamps) > max_events:
            state.timestamps.clear()
            state.blocked_until = current + block_seconds
            return max(1, int(block_seconds))
        return 0

    def reset(self, *, bucket: str) -> None:
        self._buckets.pop(bucket, None)

    def snapshot(self, *, now: float | None = None) -> ThrottleStoreSnapshot:
        current = now if now is not None else time.monotonic()
        buckets: list[ThrottleBucketSnapshot] = []
        for bucket_name in sorted(self._buckets):
            state = self._bucket(bucket=bucket_name, now=current, window_seconds=float("inf"))
            retry_after = (
                max(0, int(state.blocked_until - current)) if state.blocked_until > current else 0
            )
            buckets.append(
                ThrottleBucketSnapshot(
                    scope=_bucket_scope(bucket_name),
                    fingerprint=_bucket_fingerprint(bucket_name),
                    event_count=len(state.timestamps),
                    blocked=retry_after > 0,
                    retry_after_seconds=max(1, retry_after) if retry_after > 0 else 0,
                )
            )
        blocked_bucket_count = sum(1 for bucket in buckets if bucket.blocked)
        return ThrottleStoreSnapshot(
            storage_kind="memory",
            bucket_count=len(buckets),
            blocked_bucket_count=blocked_bucket_count,
            buckets=tuple(buckets),
        )

    def _bucket(self, *, bucket: str, now: float, window_seconds: float) -> _BucketState:
        state = self._buckets.setdefault(bucket, _BucketState())
        cutoff = now - window_seconds
        state.timestamps = [stamp for stamp in state.timestamps if stamp >= cutoff]
        if state.blocked_until <= now and not state.timestamps:
            state.blocked_until = 0.0
        return state


class SharedThrottleStore:
    def __init__(self, dsn: str, *, table_name: str = "astraauth_throttle_state") -> None:
        self._dsn = dsn
        self._dialect = infer_dialect(dsn)
        self._table_name = sql_identifier(table_name)
        self._ensure_schema()

    def retry_after(self, *, bucket: str, window_seconds: float, now: float | None = None) -> int:
        current = now if now is not None else time.monotonic()
        state = self._load(bucket=bucket, now=current, window_seconds=window_seconds)
        if state.blocked_until > current:
            return max(1, int(state.blocked_until - current))
        return 0

    def record(
        self,
        *,
        bucket: str,
        max_events: int,
        window_seconds: float,
        block_seconds: float,
        now: float | None = None,
    ) -> int:
        current = now if now is not None else time.monotonic()
        state = self._load(bucket=bucket, now=current, window_seconds=window_seconds)
        if state.blocked_until > current:
            return max(1, int(state.blocked_until - current))
        state.timestamps.append(current)
        if len(state.timestamps) > max_events:
            state.timestamps.clear()
            state.blocked_until = current + block_seconds
            self._save(bucket=bucket, state=state, updated_at=current)
            return max(1, int(block_seconds))
        self._save(bucket=bucket, state=state, updated_at=current)
        return 0

    def reset(self, *, bucket: str) -> None:
        db = create_sync_database(self._dsn)
        conn = db.connection()
        sql = compile_sql(
            "DELETE " + "FROM " + self._table_name + " WHERE bucket = {{bucket}}",
            {"bucket": bucket},
            self._dialect,
        )
        conn.execute(sql.sql, sql.params)
        conn.commit()
        db.close()

    def snapshot(self, *, now: float | None = None) -> ThrottleStoreSnapshot:
        current = now if now is not None else time.monotonic()
        db = create_sync_database(self._dsn)
        conn = db.connection()
        # nosec B608
        sql = compile_sql(
            "SELECT bucket, timestamps_json, blocked_until "
            + "FROM "
            + self._table_name
            + " ORDER BY bucket",
            {},
            self._dialect,
        )
        rows = conn.execute(sql.sql, sql.params).fetchall()
        db.close()
        buckets: list[ThrottleBucketSnapshot] = []
        for row in rows:
            bucket_name = str(row["bucket"])
            timestamps = self._decode_timestamps(row["timestamps_json"])
            blocked_until = float(row["blocked_until"] or 0.0)
            retry_after = max(0, int(blocked_until - current)) if blocked_until > current else 0
            buckets.append(
                ThrottleBucketSnapshot(
                    scope=_bucket_scope(bucket_name),
                    fingerprint=_bucket_fingerprint(bucket_name),
                    event_count=len(timestamps),
                    blocked=retry_after > 0,
                    retry_after_seconds=max(1, retry_after) if retry_after > 0 else 0,
                )
            )
        blocked_bucket_count = sum(1 for bucket in buckets if bucket.blocked)
        return ThrottleStoreSnapshot(
            storage_kind=self._dialect.value,
            bucket_count=len(buckets),
            blocked_bucket_count=blocked_bucket_count,
            buckets=tuple(buckets),
            dsn=self._dsn,
            table_name=self._table_name,
        )

    def _ensure_schema(self) -> None:
        ddl = {
            DatabaseDialect.SQLITE: (
                "CREATE " + "TABLE IF NOT EXISTS " + self._table_name + " ("
                "bucket TEXT PRIMARY KEY, "
                "timestamps_json TEXT NOT NULL, "
                "blocked_until REAL NOT NULL, "
                "updated_at REAL NOT NULL)"
            ),
            DatabaseDialect.POSTGRES: (
                "CREATE " + "TABLE IF NOT EXISTS " + self._table_name + " ("
                "bucket VARCHAR(512) PRIMARY KEY, "
                "timestamps_json TEXT NOT NULL, "
                "blocked_until DOUBLE PRECISION NOT NULL, "
                "updated_at DOUBLE PRECISION NOT NULL)"
            ),
            DatabaseDialect.MYSQL: (
                "CREATE " + "TABLE IF NOT EXISTS " + self._table_name + " ("
                "bucket VARCHAR(512) PRIMARY KEY, "
                "timestamps_json TEXT NOT NULL, "
                "blocked_until DOUBLE NOT NULL, "
                "updated_at DOUBLE NOT NULL)"
            ),
        }[self._dialect]
        db = create_sync_database(self._dsn)
        conn = db.connection()
        conn.execute(ddl)
        conn.commit()
        db.close()

    def _load(self, *, bucket: str, now: float, window_seconds: float) -> _BucketState:
        db = create_sync_database(self._dsn)
        conn = db.connection()
        sql = compile_sql(
            "SELECT timestamps_json, blocked_until "
            + "FROM "
            + self._table_name
            + " WHERE bucket = {{bucket}}",
            {"bucket": bucket},
            self._dialect,
        )
        row = conn.execute(sql.sql, sql.params).fetchone()
        db.close()
        if row is None:
            return _BucketState()
        timestamps = self._decode_timestamps(row["timestamps_json"])
        cutoff = now - window_seconds
        filtered = [stamp for stamp in timestamps if stamp >= cutoff]
        blocked_until = float(row["blocked_until"] or 0.0)
        state = _BucketState(timestamps=filtered, blocked_until=blocked_until)
        if filtered != timestamps and blocked_until <= now:
            self._save(bucket=bucket, state=state, updated_at=now)
        return state

    def _save(self, *, bucket: str, state: _BucketState, updated_at: float) -> None:
        db = create_sync_database(self._dsn)
        conn = db.connection()
        sql = upsert_sql(
            table=self._table_name,
            columns=("bucket", "timestamps_json", "blocked_until", "updated_at"),
            conflict_columns=("bucket",),
            dialect=self._dialect,
        )
        compiled = compile_sql(
            sql,
            {
                "bucket": bucket,
                "timestamps_json": json.dumps(state.timestamps),
                "blocked_until": state.blocked_until,
                "updated_at": updated_at,
            },
            self._dialect,
        )
        conn.execute(compiled.sql, compiled.params)
        conn.commit()
        db.close()

    def _decode_timestamps(self, raw: object) -> list[float]:
        if not isinstance(raw, str):
            return []
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return []
        if not isinstance(payload, Sequence):
            return []
        values: list[float] = []
        for item in payload:
            if isinstance(item, (int, float)):
                values.append(float(item))
        return values


def _bucket_scope(bucket: str) -> str:
    return bucket.split("|", 1)[0] if "|" in bucket else bucket


def _bucket_fingerprint(bucket: str) -> str:
    return sha256(bucket.encode("utf-8")).hexdigest()[:12]
