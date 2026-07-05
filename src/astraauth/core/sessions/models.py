from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from astraauth.core.ids import uuid7_str


@dataclass
class Session:
    session_id: str
    subject_id: str
    tenant_id: str
    client_id: str

    requested_scopes: set[str]

    created_at: datetime
    expires_at: datetime

    revoked: bool = False
    version: int = 1
    acr: int = 1
    amr: tuple[str, ...] = ()
    authenticated_at: datetime | None = None
    upgraded_at: datetime | None = None

    # ----------------------------------------------------------
    # Factory
    # ----------------------------------------------------------

    @classmethod
    def create(
        cls,
        *,
        subject_id: str,
        tenant_id: str,
        client_id: str,
        requested_scopes: set[str],
        ttl_seconds: int,
    ) -> Session:
        now = datetime.now(tz=UTC)

        return cls(
            session_id=uuid7_str(),
            subject_id=subject_id,
            tenant_id=tenant_id,
            client_id=client_id,
            requested_scopes=requested_scopes,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            revoked=False,
            version=1,
            acr=1,
            amr=(),
            authenticated_at=now,
            upgraded_at=None,
        )

    # ----------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------

    def rotate(self, ttl_seconds: int) -> None:
        """
        Rotate refresh token session version and extend expiry.
        """
        self.version += 1
        self.expires_at = datetime.now(tz=UTC) + timedelta(seconds=ttl_seconds)

    def is_expired(self) -> bool:
        return datetime.now(tz=UTC) >= self.expires_at

    def upgrade_authentication(
        self,
        *,
        target_acr: int,
        methods: set[str],
        at_time: datetime | None = None,
    ) -> None:
        now = at_time or datetime.now(tz=UTC)
        self.acr = max(self.acr, target_acr)
        self.amr = tuple(sorted(set(self.amr).union(methods)))
        self.authenticated_at = self.authenticated_at or now
        self.upgraded_at = now
        # Invalidate older session-bound tokens after step-up.
        self.version += 1
