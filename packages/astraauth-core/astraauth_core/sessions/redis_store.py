from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any, Protocol

from astraauth_core.sessions.models import Session
from astraauth_core.sessions.store import BaseSessionStore


class RedisLikeClient(Protocol):
    def get(self, key: str) -> str | bytes | None: ...
    def set(self, key: str, value: str, ex: int | None = None) -> Any: ...
    def scan_iter(self, match: str) -> Iterable[str | bytes]: ...


class RedisSessionStore(BaseSessionStore):
    def __init__(self, client: RedisLikeClient, *, key_prefix: str = "astraauth:session:") -> None:
        self._client = client
        self._key_prefix = key_prefix

    def _key(self, session_id: str) -> str:
        return f"{self._key_prefix}{session_id}"

    def _serialize(self, session: Session) -> str:
        return json.dumps(
            {
                "session_id": session.session_id,
                "subject_id": session.subject_id,
                "tenant_id": session.tenant_id,
                "client_id": session.client_id,
                "requested_scopes": sorted(session.requested_scopes),
                "created_at": session.created_at.replace(tzinfo=UTC).isoformat(),
                "expires_at": session.expires_at.replace(tzinfo=UTC).isoformat(),
                "revoked": session.revoked,
                "version": session.version,
                "acr": session.acr,
                "amr": list(session.amr),
                "authenticated_at": (
                    session.authenticated_at.replace(tzinfo=UTC).isoformat()
                    if session.authenticated_at is not None
                    else None
                ),
                "upgraded_at": (
                    session.upgraded_at.replace(tzinfo=UTC).isoformat()
                    if session.upgraded_at is not None
                    else None
                ),
            }
        )

    def _deserialize(self, raw: str | bytes) -> Session:
        payload = json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
        return Session(
            session_id=payload["session_id"],
            subject_id=payload["subject_id"],
            tenant_id=payload["tenant_id"],
            client_id=payload["client_id"],
            requested_scopes=set(payload["requested_scopes"]),
            created_at=datetime.fromisoformat(payload["created_at"]).replace(tzinfo=UTC),
            expires_at=datetime.fromisoformat(payload["expires_at"]).replace(tzinfo=UTC),
            revoked=bool(payload["revoked"]),
            version=int(payload["version"]),
            acr=int(payload.get("acr", 1)),
            amr=tuple(payload.get("amr", [])),
            authenticated_at=(
                datetime.fromisoformat(payload["authenticated_at"]).replace(tzinfo=UTC)
                if payload.get("authenticated_at") is not None
                else None
            ),
            upgraded_at=(
                datetime.fromisoformat(payload["upgraded_at"]).replace(tzinfo=UTC)
                if payload.get("upgraded_at") is not None
                else None
            ),
        )

    def save(self, session: Session) -> None:
        ttl = max(1, int((session.expires_at - datetime.now(tz=UTC)).total_seconds()))
        self._client.set(self._key(session.session_id), self._serialize(session), ex=ttl)

    def get(self, session_id: str) -> Session | None:
        payload = self._client.get(self._key(session_id))
        if payload is None:
            return None
        return self._deserialize(payload)

    def revoke(self, session_id: str) -> None:
        session = self.get(session_id)
        if session is None:
            return
        session.revoked = True
        self.save(session)

    def _iter_sessions(self) -> Iterable[Session]:
        pattern = f"{self._key_prefix}*"
        for key in self._client.scan_iter(pattern):
            redis_key = key.decode("utf-8") if isinstance(key, bytes) else key
            payload = self._client.get(redis_key)
            if payload is None:
                continue
            yield self._deserialize(payload)
