from astraauth.core.mfa import (
    InMemoryEmailOTPCodeStore,
    InMemoryEmailOTPFactorStore,
    InMemoryMFAChallengeStore,
    activate_email_otp_factor,
    create_email_otp_challenge,
    enroll_email_otp_factor,
    verify_email_otp_challenge,
)
from astraauth.core.sessions.models import Session


class FakeEmailDelivery:
    def __init__(self) -> None:
        self.sent: list[dict[str, str]] = []

    def send_code(self, *, email: str, code: str, tenant_id: str, subject_id: str) -> None:
        self.sent.append(
            {"email": email, "code": code, "tenant_id": tenant_id, "subject_id": subject_id}
        )


class FixedCodeGenerator:
    def generate(self, *, digits: int = 6) -> str:
        _ = digits
        return "654321"


def test_email_otp_challenge_flow() -> None:
    factor_store = InMemoryEmailOTPFactorStore()
    code_store = InMemoryEmailOTPCodeStore()
    challenge_store = InMemoryMFAChallengeStore()
    delivery = FakeEmailDelivery()
    session = Session.create(
        subject_id="user-1",
        tenant_id="tenant-1",
        client_id="client-1",
        requested_scopes={"openid"},
        ttl_seconds=300,
    )

    factor = enroll_email_otp_factor(
        subject_id="user-1",
        tenant_id="tenant-1",
        email="user-1@example.com",
        issuer="AstraAuth",
        factor_store=factor_store,
    ).factor
    activate_email_otp_factor(factor_id=factor.factor_id, factor_store=factor_store)

    delivery_result = create_email_otp_challenge(
        session=session,
        challenge_store=challenge_store,
        factor_store=factor_store,
        code_store=code_store,
        delivery=delivery,
        code_generator=FixedCodeGenerator(),
        required_acr=2,
        purpose="step_up",
        ttl_seconds=120,
    )
    assert delivery_result.destination == "user-1@example.com"
    assert delivery.sent[0]["code"] == "654321"

    verified = verify_email_otp_challenge(
        challenge_id=delivery_result.challenge.challenge_id,
        session=session,
        code="654321",
        challenge_store=challenge_store,
        code_store=code_store,
    )
    assert verified.verified_at is not None
