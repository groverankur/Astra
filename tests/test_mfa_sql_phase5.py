from astraauth.core.mfa import (
    EmailOTPCode,
    EmailOTPFactor,
    MFAChallenge,
    MFAFactorType,
    SQLEmailOTPCodeStore,
    SQLEmailOTPFactorStore,
    SQLMFAChallengeStore,
    SQLTOTPFactorStore,
    TOTPFactor,
)


def test_sql_mfa_stores_roundtrip() -> None:
    dsn = ":memory:"
    challenge_store = SQLMFAChallengeStore(dsn)
    totp_store = SQLTOTPFactorStore(dsn)
    email_factor_store = SQLEmailOTPFactorStore(dsn)
    email_code_store = SQLEmailOTPCodeStore(dsn)

    challenge = MFAChallenge.issue(
        session_id="s1",
        subject_id="u1",
        tenant_id="t1",
        factor_type=MFAFactorType.TOTP,
        required_acr=2,
        purpose="step_up",
        ttl_seconds=120,
    )
    challenge_store.save(challenge)
    fetched_challenge = challenge_store.get(challenge.challenge_id)
    assert fetched_challenge is not None
    assert fetched_challenge.factor_type == MFAFactorType.TOTP

    totp = TOTPFactor.enroll(
        subject_id="u1",
        tenant_id="t1",
        secret="SECRET",
        issuer="AstraAuth",
        account_name="u1@example.com",
    )
    totp.activate()
    totp_store.save(totp)
    fetched_totp = totp_store.get(totp.factor_id)
    assert fetched_totp is not None
    assert fetched_totp.enabled is True
    assert totp_store.get_active_for_subject(subject_id="u1", tenant_id="t1") is not None

    email_factor = EmailOTPFactor.enroll(
        subject_id="u1",
        tenant_id="t1",
        email="u1@example.com",
        issuer="AstraAuth",
    )
    email_factor.activate()
    email_factor_store.save(email_factor)
    fetched_email_factor = email_factor_store.get(email_factor.factor_id)
    assert fetched_email_factor is not None
    assert fetched_email_factor.email == "u1@example.com"

    email_code = EmailOTPCode.issue(
        challenge_id=challenge.challenge_id,
        factor_id=email_factor.factor_id,
        code="123456",
        ttl_seconds=120,
    )
    email_code_store.save(email_code)
    fetched_email_code = email_code_store.get(challenge.challenge_id)
    assert fetched_email_code is not None
    assert fetched_email_code.code == "123456"
