from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from astraauth_core.ids import new_uuid7_str


class MFAFactorType(StrEnum):
    TOTP = "totp"
    EMAIL_OTP = "email_otp"
    WEBAUTHN = "webauthn"


class MFAChallengeStatus(StrEnum):
    PENDING = "pending"
    VERIFIED = "verified"
    CANCELLED = "cancelled"


@dataclass
class TOTPFactor:
    factor_id: str
    subject_id: str
    tenant_id: str
    secret: str
    issuer: str
    account_name: str
    digits: int
    period: int
    algorithm: str
    created_at: datetime
    enabled: bool = False
    verified_at: datetime | None = None

    @classmethod
    def enroll(
        cls,
        *,
        subject_id: str,
        tenant_id: str,
        secret: str,
        issuer: str,
        account_name: str,
        digits: int = 6,
        period: int = 30,
        algorithm: str = "SHA1",
    ) -> TOTPFactor:
        return cls(
            factor_id=new_uuid7_str(),
            subject_id=subject_id,
            tenant_id=tenant_id,
            secret=secret,
            issuer=issuer,
            account_name=account_name,
            digits=digits,
            period=period,
            algorithm=algorithm,
            created_at=datetime.now(tz=UTC),
            enabled=False,
            verified_at=None,
        )

    def activate(self, at_time: datetime | None = None) -> None:
        self.enabled = True
        self.verified_at = at_time or datetime.now(tz=UTC)


@dataclass
class EmailOTPFactor:
    factor_id: str
    subject_id: str
    tenant_id: str
    email: str
    issuer: str
    created_at: datetime
    enabled: bool = False
    verified_at: datetime | None = None

    @classmethod
    def enroll(
        cls,
        *,
        subject_id: str,
        tenant_id: str,
        email: str,
        issuer: str,
    ) -> EmailOTPFactor:
        return cls(
            factor_id=new_uuid7_str(),
            subject_id=subject_id,
            tenant_id=tenant_id,
            email=email,
            issuer=issuer,
            created_at=datetime.now(tz=UTC),
            enabled=False,
            verified_at=None,
        )

    def activate(self, at_time: datetime | None = None) -> None:
        self.enabled = True
        self.verified_at = at_time or datetime.now(tz=UTC)


@dataclass
class EmailOTPCode:
    challenge_id: str
    factor_id: str
    code: str
    created_at: datetime
    expires_at: datetime
    consumed_at: datetime | None = None

    @classmethod
    def issue(
        cls,
        *,
        challenge_id: str,
        factor_id: str,
        code: str,
        ttl_seconds: int,
    ) -> EmailOTPCode:
        now = datetime.now(tz=UTC)
        return cls(
            challenge_id=challenge_id,
            factor_id=factor_id,
            code=code,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            consumed_at=None,
        )

    def is_expired(self) -> bool:
        return datetime.now(tz=UTC) >= self.expires_at

    def consume(self, at_time: datetime | None = None) -> None:
        self.consumed_at = at_time or datetime.now(tz=UTC)


@dataclass
class MFAChallenge:
    challenge_id: str
    session_id: str
    subject_id: str
    tenant_id: str
    factor_type: MFAFactorType
    required_acr: int
    purpose: str
    created_at: datetime
    expires_at: datetime
    status: MFAChallengeStatus = MFAChallengeStatus.PENDING
    verified_at: datetime | None = None

    @classmethod
    def issue(
        cls,
        *,
        session_id: str,
        subject_id: str,
        tenant_id: str,
        factor_type: MFAFactorType,
        required_acr: int,
        purpose: str,
        ttl_seconds: int,
    ) -> MFAChallenge:
        now = datetime.now(tz=UTC)
        return cls(
            challenge_id=new_uuid7_str(),
            session_id=session_id,
            subject_id=subject_id,
            tenant_id=tenant_id,
            factor_type=factor_type,
            required_acr=required_acr,
            purpose=purpose,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            status=MFAChallengeStatus.PENDING,
            verified_at=None,
        )

    def is_expired(self) -> bool:
        return datetime.now(tz=UTC) >= self.expires_at

    def verify(self, at_time: datetime | None = None) -> None:
        self.status = MFAChallengeStatus.VERIFIED
        self.verified_at = at_time or datetime.now(tz=UTC)
