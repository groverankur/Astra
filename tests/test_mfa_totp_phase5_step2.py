from astraauth.core.mfa import (
    InMemoryMFAChallengeStore,
    InMemoryTOTPFactorStore,
    MFAFactorType,
    TOTPVerificationError,
    activate_totp_factor,
    create_mfa_challenge,
    enroll_totp_factor,
    verify_totp_challenge,
)
from astraauth.core.sessions.models import Session


class FakeTOTPProvider:
    def __init__(self) -> None:
        self.secret = "BASE32SECRET"

    def generate_secret(self) -> str:
        return self.secret

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
        return (
            f"otpauth://totp/{issuer}:{account_name}"
            f"?secret={secret}&issuer={issuer}&digits={digits}&period={period}&algorithm={algorithm}"
        )

    def verify(
        self,
        *,
        secret: str,
        code: str,
        digits: int,
        period: int,
        algorithm: str,
    ) -> bool:
        return secret == self.secret and code == "123456"


def test_totp_enrollment_activation_and_challenge_verification() -> None:
    provider = FakeTOTPProvider()
    factor_store = InMemoryTOTPFactorStore()
    challenge_store = InMemoryMFAChallengeStore()
    session = Session.create(
        subject_id="user-1",
        tenant_id="tenant-1",
        client_id="client-1",
        requested_scopes={"openid"},
        ttl_seconds=300,
    )

    enrollment = enroll_totp_factor(
        subject_id="user-1",
        tenant_id="tenant-1",
        issuer="AstraAuth",
        account_name="user-1@example.com",
        factor_store=factor_store,
        provider=provider,
    )
    assert enrollment.factor.enabled is False
    assert enrollment.factor.secret == "BASE32SECRET"
    assert enrollment.provisioning_uri.startswith("otpauth://totp/AstraAuth:user-1@example.com")

    activated = activate_totp_factor(
        factor_id=enrollment.factor.factor_id,
        code="123456",
        factor_store=factor_store,
        provider=provider,
    )
    assert activated.enabled is True
    assert activated.verified_at is not None

    challenge = create_mfa_challenge(
        session=session,
        factor_type=MFAFactorType.TOTP,
        challenge_store=challenge_store,
        required_acr=2,
        purpose="step_up",
        ttl_seconds=120,
    )
    verified = verify_totp_challenge(
        challenge_id=challenge.challenge_id,
        session=session,
        code="123456",
        challenge_store=challenge_store,
        factor_store=factor_store,
        provider=provider,
    )
    assert verified.verified_at is not None


def test_totp_activation_rejects_invalid_code() -> None:
    provider = FakeTOTPProvider()
    factor_store = InMemoryTOTPFactorStore()
    enrollment = enroll_totp_factor(
        subject_id="user-1",
        tenant_id="tenant-1",
        issuer="AstraAuth",
        account_name="user-1@example.com",
        factor_store=factor_store,
        provider=provider,
    )

    try:
        activate_totp_factor(
            factor_id=enrollment.factor.factor_id,
            code="000000",
            factor_store=factor_store,
            provider=provider,
        )
    except TOTPVerificationError:
        pass
    else:
        raise AssertionError("expected invalid TOTP code to fail")
