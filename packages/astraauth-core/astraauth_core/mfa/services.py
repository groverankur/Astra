from __future__ import annotations

from secrets import randbelow, token_bytes
from typing import Protocol, cast

from astraauth_core.events.base import EventBus
from astraauth_core.mfa.models import (
    EmailOTPCode,
    EmailOTPFactor,
    MFAChallenge,
    MFAChallengeStatus,
    MFAFactorType,
    TOTPFactor,
)
from astraauth_core.mfa.store import (
    EmailOTPCodeStore,
    EmailOTPFactorStore,
    MFAChallengeStore,
    TOTPFactorStore,
)
from astraauth_core.sessions.models import Session
from astraauth_core.sessions.store import SessionStore


class MFAChallengeError(Exception):
    pass


class MFAChallengeExpiredError(MFAChallengeError):
    pass


class MFAChallengeStateError(MFAChallengeError):
    pass


class MFAChallengeSessionMismatchError(MFAChallengeError):
    pass


class MFAChallengeSubjectMismatchError(MFAChallengeError):
    pass


class MFASessionUpgradeError(MFAChallengeError):
    pass


class TOTPVerificationError(MFAChallengeError):
    pass


class EmailOTPVerificationError(MFAChallengeError):
    pass


class TOTPProvider(Protocol):
    def generate_secret(self) -> str: ...

    def build_uri(
        self,
        *,
        secret: str,
        issuer: str,
        account_name: str,
        digits: int,
        period: int,
        algorithm: str,
    ) -> str: ...

    def verify(
        self,
        *,
        secret: str,
        code: str,
        digits: int,
        period: int,
        algorithm: str,
    ) -> bool: ...


class EmailOTPCodeGenerator(Protocol):
    def generate(self, *, digits: int = 6) -> str: ...


class EmailOTPDelivery(Protocol):
    def send_code(self, *, email: str, code: str, tenant_id: str, subject_id: str) -> None: ...


class OTPAuthTOTPProvider:
    def generate_secret(self) -> str:
        from base64 import b32encode

        return b32encode(token_bytes(20)).decode("ascii").rstrip("=")

    def build_uri(
        self,
        *,
        secret: str,
        issuer: str,
        account_name: str,
        digits: int,
        period: int,
        algorithm: str,
    ) -> str:
        try:
            from otpauth import TOTP
        except ImportError as exc:
            raise RuntimeError(
                "Install astraauth-core with the 'otp' extra to use the OTPAuth TOTP provider"
            ) from exc

        totp = TOTP(secret=secret, issuer=issuer, label=account_name, digits=digits, period=period)
        return cast(str, totp.to_uri())

    def verify(
        self,
        *,
        secret: str,
        code: str,
        digits: int,
        period: int,
        algorithm: str,
    ) -> bool:
        try:
            from otpauth import TOTP
        except ImportError as exc:
            raise RuntimeError(
                "Install astraauth-core with the 'otp' extra to use the OTPAuth TOTP provider"
            ) from exc

        totp = TOTP(secret=secret, digits=digits, period=period)
        return bool(totp.verify(code))


class NumericEmailOTPGenerator:
    def generate(self, *, digits: int = 6) -> str:
        upper = 10**digits
        return str(randbelow(upper)).zfill(digits)


class TOTPEnrollment:
    def __init__(self, factor: TOTPFactor, provisioning_uri: str) -> None:
        self.factor = factor
        self.provisioning_uri = provisioning_uri


class EmailOTPEnrollment:
    def __init__(self, factor: EmailOTPFactor) -> None:
        self.factor = factor


class EmailOTPChallengeDelivery:
    def __init__(self, challenge: MFAChallenge, destination: str) -> None:
        self.challenge = challenge
        self.destination = destination



def create_mfa_challenge(
    *,
    session: Session,
    factor_type: MFAFactorType,
    challenge_store: MFAChallengeStore,
    required_acr: int,
    purpose: str,
    ttl_seconds: int,
    event_bus: EventBus | None = None,
) -> MFAChallenge:
    challenge = MFAChallenge.issue(
        session_id=session.session_id,
        subject_id=session.subject_id,
        tenant_id=session.tenant_id,
        factor_type=factor_type,
        required_acr=required_acr,
        purpose=purpose,
        ttl_seconds=ttl_seconds,
    )
    challenge_store.save(challenge)

    if event_bus is not None:
        event_bus.publish(
            "mfa.challenge",
            {
                "challenge_id": challenge.challenge_id,
                "sid": challenge.session_id,
                "sub": challenge.subject_id,
                "tid": challenge.tenant_id,
                "factor_type": challenge.factor_type.value,
                "required_acr": challenge.required_acr,
            },
        )

    return challenge



def verify_mfa_challenge(
    *,
    challenge_id: str,
    challenge_store: MFAChallengeStore,
    session: Session,
) -> MFAChallenge:
    challenge = challenge_store.get(challenge_id)
    if challenge is None:
        raise MFAChallengeError("Unknown MFA challenge")

    if challenge.session_id != session.session_id:
        raise MFAChallengeSessionMismatchError("Challenge does not belong to the provided session")

    if challenge.subject_id != session.subject_id or challenge.tenant_id != session.tenant_id:
        raise MFAChallengeSubjectMismatchError("Challenge subject or tenant mismatch")

    if challenge.is_expired():
        raise MFAChallengeExpiredError("MFA challenge expired")

    if challenge.status != MFAChallengeStatus.PENDING:
        raise MFAChallengeStateError("MFA challenge is not pending")

    challenge.verify()
    challenge_store.save(challenge)
    return challenge



def enroll_totp_factor(
    *,
    subject_id: str,
    tenant_id: str,
    issuer: str,
    account_name: str,
    factor_store: TOTPFactorStore,
    provider: TOTPProvider,
    digits: int = 6,
    period: int = 30,
    algorithm: str = "SHA1",
) -> TOTPEnrollment:
    factor = TOTPFactor.enroll(
        subject_id=subject_id,
        tenant_id=tenant_id,
        secret=provider.generate_secret(),
        issuer=issuer,
        account_name=account_name,
        digits=digits,
        period=period,
        algorithm=algorithm,
    )
    factor_store.save(factor)
    provisioning_uri = provider.build_uri(
        secret=factor.secret,
        issuer=factor.issuer,
        account_name=factor.account_name,
        digits=factor.digits,
        period=factor.period,
        algorithm=factor.algorithm,
    )
    return TOTPEnrollment(factor=factor, provisioning_uri=provisioning_uri)



def activate_totp_factor(
    *,
    factor_id: str,
    code: str,
    factor_store: TOTPFactorStore,
    provider: TOTPProvider,
) -> TOTPFactor:
    factor = factor_store.get(factor_id)
    if factor is None:
        raise TOTPVerificationError("Unknown TOTP factor")

    if not provider.verify(
        secret=factor.secret,
        code=code,
        digits=factor.digits,
        period=factor.period,
        algorithm=factor.algorithm,
    ):
        raise TOTPVerificationError("Invalid TOTP code")

    factor.activate()
    factor_store.save(factor)
    return factor



def verify_totp_challenge(
    *,
    challenge_id: str,
    session: Session,
    code: str,
    challenge_store: MFAChallengeStore,
    factor_store: TOTPFactorStore,
    provider: TOTPProvider,
) -> MFAChallenge:
    factor = factor_store.get_active_for_subject(
        subject_id=session.subject_id,
        tenant_id=session.tenant_id,
    )
    if factor is None:
        raise TOTPVerificationError("No active TOTP factor for subject")

    if not provider.verify(
        secret=factor.secret,
        code=code,
        digits=factor.digits,
        period=factor.period,
        algorithm=factor.algorithm,
    ):
        raise TOTPVerificationError("Invalid TOTP code")

    return verify_mfa_challenge(
        challenge_id=challenge_id,
        challenge_store=challenge_store,
        session=session,
    )



def enroll_email_otp_factor(
    *,
    subject_id: str,
    tenant_id: str,
    email: str,
    issuer: str,
    factor_store: EmailOTPFactorStore,
) -> EmailOTPEnrollment:
    factor = EmailOTPFactor.enroll(
        subject_id=subject_id,
        tenant_id=tenant_id,
        email=email,
        issuer=issuer,
    )
    factor_store.save(factor)
    return EmailOTPEnrollment(factor=factor)



def activate_email_otp_factor(
    *,
    factor_id: str,
    factor_store: EmailOTPFactorStore,
) -> EmailOTPFactor:
    factor = factor_store.get(factor_id)
    if factor is None:
        raise EmailOTPVerificationError("Unknown email OTP factor")
    factor.activate()
    factor_store.save(factor)
    return factor



def create_email_otp_challenge(
    *,
    session: Session,
    challenge_store: MFAChallengeStore,
    factor_store: EmailOTPFactorStore,
    code_store: EmailOTPCodeStore,
    delivery: EmailOTPDelivery,
    code_generator: EmailOTPCodeGenerator,
    required_acr: int,
    purpose: str,
    ttl_seconds: int,
    event_bus: EventBus | None = None,
) -> EmailOTPChallengeDelivery:
    factor = factor_store.get_active_for_subject(
        subject_id=session.subject_id,
        tenant_id=session.tenant_id,
    )
    if factor is None:
        raise EmailOTPVerificationError("No active email OTP factor for subject")

    challenge = create_mfa_challenge(
        session=session,
        factor_type=MFAFactorType.EMAIL_OTP,
        challenge_store=challenge_store,
        required_acr=required_acr,
        purpose=purpose,
        ttl_seconds=ttl_seconds,
        event_bus=event_bus,
    )
    code = EmailOTPCode.issue(
        challenge_id=challenge.challenge_id,
        factor_id=factor.factor_id,
        code=code_generator.generate(),
        ttl_seconds=ttl_seconds,
    )
    code_store.save(code)
    delivery.send_code(
        email=factor.email,
        code=code.code,
        tenant_id=session.tenant_id,
        subject_id=session.subject_id,
    )
    return EmailOTPChallengeDelivery(challenge=challenge, destination=factor.email)



def verify_email_otp_challenge(
    *,
    challenge_id: str,
    session: Session,
    code: str,
    challenge_store: MFAChallengeStore,
    code_store: EmailOTPCodeStore,
) -> MFAChallenge:
    otp_code = code_store.get(challenge_id)
    if otp_code is None:
        raise EmailOTPVerificationError("Unknown email OTP challenge code")
    if otp_code.consumed_at is not None:
        raise EmailOTPVerificationError("Email OTP code already consumed")
    if otp_code.is_expired():
        raise EmailOTPVerificationError("Email OTP code expired")
    if otp_code.code != code:
        raise EmailOTPVerificationError("Invalid email OTP code")

    otp_code.consume()
    code_store.save(otp_code)
    return verify_mfa_challenge(
        challenge_id=challenge_id,
        challenge_store=challenge_store,
        session=session,
    )



def upgrade_session_with_verified_challenge(
    *,
    challenge_id: str,
    challenge_store: MFAChallengeStore,
    session_store: SessionStore,
    methods: set[str],
    event_bus: EventBus | None = None,
) -> Session:
    challenge = challenge_store.get(challenge_id)
    if challenge is None:
        raise MFASessionUpgradeError("Unknown MFA challenge")

    if challenge.is_expired():
        raise MFAChallengeExpiredError("MFA challenge expired")

    if challenge.status != MFAChallengeStatus.VERIFIED:
        raise MFAChallengeStateError("MFA challenge must be verified before session upgrade")

    session = session_store.get(challenge.session_id)
    if session is None:
        raise MFASessionUpgradeError("Unknown session for verified MFA challenge")

    if session.revoked or session.is_expired():
        raise MFASessionUpgradeError("Session is not eligible for MFA upgrade")

    session.upgrade_authentication(target_acr=challenge.required_acr, methods=methods)
    session_store.save(session)

    if event_bus is not None:
        event_bus.publish(
            "session.upgraded",
            {
                "sid": session.session_id,
                "sub": session.subject_id,
                "tid": session.tenant_id,
                "acr": session.acr,
                "amr": list(session.amr),
            },
        )

    return session

