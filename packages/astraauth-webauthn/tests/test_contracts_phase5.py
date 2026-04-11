from datetime import UTC, datetime, timedelta

import pytest
from astraauth_core.mfa import InMemoryMFAChallengeStore, MFAFactorType, create_mfa_challenge
from astraauth_core.sessions.models import Session
from astraauth_webauthn import (
    AsyncSQLWebAuthnAuthenticationStateRepository,
    AsyncSQLWebAuthnCredentialRepository,
    AsyncSQLWebAuthnRegistrationStateRepository,
    InMemoryWebAuthnAuthenticationStateRepository,
    InMemoryWebAuthnCredentialRepository,
    InMemoryWebAuthnRegistrationStateRepository,
    LocalDevelopmentWebAuthnVerifier,
    ProductionBaselineWebAuthnVerifier,
    SQLWebAuthnAuthenticationStateRepository,
    SQLWebAuthnCredentialRepository,
    SQLWebAuthnRegistrationStateRepository,
    WebAuthnError,
    WebAuthnVerificationError,
    begin_authentication_for_mfa,
    begin_registration,
    finish_authentication_for_mfa,
    finish_registration,
)


def test_webauthn_registration_and_mfa_authentication_contracts() -> None:
    registration_states = InMemoryWebAuthnRegistrationStateRepository()
    authentication_states = InMemoryWebAuthnAuthenticationStateRepository()
    credentials = InMemoryWebAuthnCredentialRepository()
    challenge_store = InMemoryMFAChallengeStore()
    session = Session.create(
        subject_id="user-1",
        tenant_id="tenant-1",
        client_id="client-1",
        requested_scopes={"openid"},
        ttl_seconds=300,
    )

    registration = begin_registration(
        session=session,
        user_name="user-1@example.com",
        rp_id="example.com",
        rp_name="Example",
        state_repository=registration_states,
    )
    credential = finish_registration(
        state_id=registration.state.state_id,
        credential_id="cred-1",
        public_key="public-key",
        transports=("internal",),
        sign_count=1,
        credential_repository=credentials,
        state_repository=registration_states,
        verifier=LocalDevelopmentWebAuthnVerifier(),
    )
    assert credential.credential_id == "cred-1"
    assert registration_states.get(registration.state.state_id) is None

    mfa_challenge = create_mfa_challenge(
        session=session,
        factor_type=MFAFactorType.WEBAUTHN,
        challenge_store=challenge_store,
        required_acr=2,
        purpose="step_up",
        ttl_seconds=120,
    )
    authn = begin_authentication_for_mfa(
        session=session,
        mfa_challenge_id=mfa_challenge.challenge_id,
        credential_repository=credentials,
        state_repository=authentication_states,
    )
    verified = finish_authentication_for_mfa(
        state_id=authn.state.state_id,
        session=session,
        credential_id="cred-1",
        new_sign_count=2,
        credential_repository=credentials,
        state_repository=authentication_states,
        challenge_store=challenge_store,
        verifier=LocalDevelopmentWebAuthnVerifier(),
    )
    assert verified.verified_at is not None
    assert authentication_states.get(authn.state.state_id) is None


def test_webauthn_sql_repositories_roundtrip() -> None:
    dsn = ":memory:"
    credentials = SQLWebAuthnCredentialRepository(dsn)
    registration_states = SQLWebAuthnRegistrationStateRepository(dsn)
    authentication_states = SQLWebAuthnAuthenticationStateRepository(dsn)
    challenge_store = InMemoryMFAChallengeStore()
    session = Session.create(
        subject_id="user-1",
        tenant_id="tenant-1",
        client_id="client-1",
        requested_scopes={"openid"},
        ttl_seconds=300,
    )

    registration = begin_registration(
        session=session,
        user_name="user-1@example.com",
        rp_id="example.com",
        rp_name="Example",
        state_repository=registration_states,
    )
    credential = finish_registration(
        state_id=registration.state.state_id,
        credential_id="cred-sql-1",
        public_key="public-key",
        transports=("internal",),
        sign_count=1,
        credential_repository=credentials,
        state_repository=registration_states,
    )
    assert credentials.get(credential.credential_id) is not None
    assert registration_states.get(registration.state.state_id) is None

    mfa_challenge = create_mfa_challenge(
        session=session,
        factor_type=MFAFactorType.WEBAUTHN,
        challenge_store=challenge_store,
        required_acr=2,
        purpose="step_up",
        ttl_seconds=120,
    )
    authn = begin_authentication_for_mfa(
        session=session,
        mfa_challenge_id=mfa_challenge.challenge_id,
        credential_repository=credentials,
        state_repository=authentication_states,
    )
    verified = finish_authentication_for_mfa(
        state_id=authn.state.state_id,
        session=session,
        credential_id="cred-sql-1",
        new_sign_count=3,
        credential_repository=credentials,
        state_repository=authentication_states,
        challenge_store=challenge_store,
    )
    assert verified.verified_at is not None
    persisted = credentials.get("cred-sql-1")
    assert persisted is not None
    assert persisted.sign_count == 3
    assert authentication_states.get(authn.state.state_id) is None


@pytest.mark.asyncio
async def test_webauthn_async_sql_repositories_roundtrip() -> None:
    credentials = AsyncSQLWebAuthnCredentialRepository(":memory:")
    registration_states = AsyncSQLWebAuthnRegistrationStateRepository(":memory:")
    authentication_states = AsyncSQLWebAuthnAuthenticationStateRepository(":memory:")

    await credentials.ensure_schema()
    await registration_states.ensure_schema()
    await authentication_states.ensure_schema()

    session = Session.create(
        subject_id="user-async",
        tenant_id="tenant-async",
        client_id="client-async",
        requested_scopes={"openid"},
        ttl_seconds=300,
    )
    registration = begin_registration(
        session=session,
        user_name="user-async@example.com",
        rp_id="example.com",
        rp_name="Example",
        state_repository=InMemoryWebAuthnRegistrationStateRepository(),
    )
    await registration_states.save(registration.state)
    loaded_registration = await registration_states.get(registration.state.state_id)
    assert loaded_registration is not None
    await registration_states.delete(registration.state.state_id)
    assert await registration_states.get(registration.state.state_id) is None

    from astraauth_webauthn.models import WebAuthnAuthenticationState, WebAuthnCredential

    credential = WebAuthnCredential(
        credential_id="cred-async-1",
        subject_id="user-async",
        tenant_id="tenant-async",
        public_key="public-key",
        sign_count=1,
        transports=("internal",),
        created_at=registration.state.created_at,
    )
    await credentials.save(credential)
    assert await credentials.get("cred-async-1") is not None

    auth_state = WebAuthnAuthenticationState.issue(
        mfa_challenge_id="challenge-1",
        session_id=session.session_id,
        subject_id=session.subject_id,
        tenant_id=session.tenant_id,
        challenge="challenge",
        ttl_seconds=300,
    )
    await authentication_states.save(auth_state)
    assert await authentication_states.get(auth_state.state_id) is not None
    await authentication_states.delete(auth_state.state_id)
    assert await authentication_states.get(auth_state.state_id) is None


def test_webauthn_rejects_expired_registration_state() -> None:
    registration_states = InMemoryWebAuthnRegistrationStateRepository()
    credentials = InMemoryWebAuthnCredentialRepository()
    session = Session.create(
        subject_id="user-1",
        tenant_id="tenant-1",
        client_id="client-1",
        requested_scopes={"openid"},
        ttl_seconds=300,
    )
    registration = begin_registration(
        session=session,
        user_name="user-1@example.com",
        rp_id="example.com",
        rp_name="Example",
        state_repository=registration_states,
        ttl_seconds=1,
    )
    registration.state.expires_at = datetime.now(tz=UTC) - timedelta(seconds=1)
    registration_states.save(registration.state)

    with pytest.raises(WebAuthnError):
        finish_registration(
            state_id=registration.state.state_id,
            credential_id="cred-expired",
            public_key="public-key",
            transports=("internal",),
            sign_count=1,
            credential_repository=credentials,
            state_repository=registration_states,
        )


def test_webauthn_rejects_sign_count_regression() -> None:
    registration_states = InMemoryWebAuthnRegistrationStateRepository()
    authentication_states = InMemoryWebAuthnAuthenticationStateRepository()
    credentials = InMemoryWebAuthnCredentialRepository()
    challenge_store = InMemoryMFAChallengeStore()
    session = Session.create(
        subject_id="user-1",
        tenant_id="tenant-1",
        client_id="client-1",
        requested_scopes={"openid"},
        ttl_seconds=300,
    )
    registration = begin_registration(
        session=session,
        user_name="user-1@example.com",
        rp_id="example.com",
        rp_name="Example",
        state_repository=registration_states,
    )
    finish_registration(
        state_id=registration.state.state_id,
        credential_id="cred-1",
        public_key="public-key",
        transports=("internal",),
        sign_count=5,
        credential_repository=credentials,
        state_repository=registration_states,
    )
    mfa_challenge = create_mfa_challenge(
        session=session,
        factor_type=MFAFactorType.WEBAUTHN,
        challenge_store=challenge_store,
        required_acr=2,
        purpose="step_up",
        ttl_seconds=120,
    )
    authn = begin_authentication_for_mfa(
        session=session,
        mfa_challenge_id=mfa_challenge.challenge_id,
        credential_repository=credentials,
        state_repository=authentication_states,
    )

    with pytest.raises(WebAuthnVerificationError):
        finish_authentication_for_mfa(
            state_id=authn.state.state_id,
            session=session,
            credential_id="cred-1",
            new_sign_count=4,
            credential_repository=credentials,
            state_repository=authentication_states,
            challenge_store=challenge_store,
        )


def test_webauthn_rejects_replayed_authentication_state() -> None:
    registration_states = InMemoryWebAuthnRegistrationStateRepository()
    authentication_states = InMemoryWebAuthnAuthenticationStateRepository()
    credentials = InMemoryWebAuthnCredentialRepository()
    challenge_store = InMemoryMFAChallengeStore()
    session = Session.create(
        subject_id="user-1",
        tenant_id="tenant-1",
        client_id="client-1",
        requested_scopes={"openid"},
        ttl_seconds=300,
    )
    registration = begin_registration(
        session=session,
        user_name="user-1@example.com",
        rp_id="example.com",
        rp_name="Example",
        state_repository=registration_states,
    )
    finish_registration(
        state_id=registration.state.state_id,
        credential_id="cred-replay",
        public_key="public-key",
        transports=("internal",),
        sign_count=1,
        credential_repository=credentials,
        state_repository=registration_states,
        verifier=ProductionBaselineWebAuthnVerifier(),
    )
    challenge = create_mfa_challenge(
        session=session,
        factor_type=MFAFactorType.WEBAUTHN,
        challenge_store=challenge_store,
        required_acr=2,
        purpose="step_up",
        ttl_seconds=120,
    )
    authn = begin_authentication_for_mfa(
        session=session,
        mfa_challenge_id=challenge.challenge_id,
        credential_repository=credentials,
        state_repository=authentication_states,
    )
    first = finish_authentication_for_mfa(
        state_id=authn.state.state_id,
        session=session,
        credential_id="cred-replay",
        new_sign_count=2,
        credential_repository=credentials,
        state_repository=authentication_states,
        challenge_store=challenge_store,
        verifier=ProductionBaselineWebAuthnVerifier(),
    )
    assert first.verified_at is not None

    with pytest.raises(WebAuthnError):
        finish_authentication_for_mfa(
            state_id=authn.state.state_id,
            session=session,
            credential_id="cred-replay",
            new_sign_count=3,
            credential_repository=credentials,
            state_repository=authentication_states,
            challenge_store=challenge_store,
            verifier=ProductionBaselineWebAuthnVerifier(),
        )


def test_webauthn_production_verifier_rejects_non_advanced_sign_count() -> None:
    verifier = ProductionBaselineWebAuthnVerifier()
    credential = type('Credential', (), {'public_key': 'public-key', 'sign_count': 5})()
    state = type('State', (), {'challenge': 'challenge'})()

    with pytest.raises(WebAuthnVerificationError):
        verifier.verify_authentication(
            state=state,
            credential=credential,
            new_sign_count=5,
        )


def test_webauthn_production_verifier_rejects_empty_registration_material() -> None:
    verifier = ProductionBaselineWebAuthnVerifier()
    state = Session.create(
        subject_id="user-1",
        tenant_id="tenant-1",
        client_id="client-1",
        requested_scopes={"openid"},
        ttl_seconds=300,
    )

    with pytest.raises(WebAuthnVerificationError):
        verifier.verify_registration(
            state=type('RegistrationState', (), {'session_id': state.session_id})(),
            credential_id="",
            public_key="public-key",
            transports=("internal",),
            sign_count=1,
        )
