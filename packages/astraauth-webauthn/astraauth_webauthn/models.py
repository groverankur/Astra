from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from astraauth_core.ids import new_uuid7_str


@dataclass
class WebAuthnCredential:
    credential_id: str
    subject_id: str
    tenant_id: str
    public_key: str
    sign_count: int
    transports: tuple[str, ...]
    created_at: datetime


@dataclass
class WebAuthnRegistrationState:
    state_id: str
    session_id: str
    subject_id: str
    tenant_id: str
    challenge: str
    user_name: str
    created_at: datetime
    expires_at: datetime

    @classmethod
    def issue(
        cls,
        *,
        session_id: str,
        subject_id: str,
        tenant_id: str,
        challenge: str,
        user_name: str,
        ttl_seconds: int,
    ) -> WebAuthnRegistrationState:
        now = datetime.now(tz=UTC)
        return cls(
            state_id=new_uuid7_str(),
            session_id=session_id,
            subject_id=subject_id,
            tenant_id=tenant_id,
            challenge=challenge,
            user_name=user_name,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )

    def is_expired(self) -> bool:
        return datetime.now(tz=UTC) >= self.expires_at


@dataclass
class WebAuthnAuthenticationState:
    state_id: str
    mfa_challenge_id: str
    session_id: str
    subject_id: str
    tenant_id: str
    challenge: str
    created_at: datetime
    expires_at: datetime

    @classmethod
    def issue(
        cls,
        *,
        mfa_challenge_id: str,
        session_id: str,
        subject_id: str,
        tenant_id: str,
        challenge: str,
        ttl_seconds: int,
    ) -> WebAuthnAuthenticationState:
        now = datetime.now(tz=UTC)
        return cls(
            state_id=new_uuid7_str(),
            mfa_challenge_id=mfa_challenge_id,
            session_id=session_id,
            subject_id=subject_id,
            tenant_id=tenant_id,
            challenge=challenge,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )

    def is_expired(self) -> bool:
        return datetime.now(tz=UTC) >= self.expires_at
