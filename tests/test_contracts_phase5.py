import json
import sys
from datetime import UTC, datetime, timedelta
from types import ModuleType

import pytest

import astraauth.webauthn as webauthn
from astraauth.core.mfa import InMemoryMFAChallengeStore, MFAFactorType, create_mfa_challenge
from astraauth.core.sessions.models import Session
from astraauth.webauthn import services as webauthn_services


class _FakeWebAuthnModule(ModuleType):
    def verify_registration_response(self, **_: object) -> None:
        return None

    def verify_authentication_response(self, **_: object) -> None:
        return None


def _dev_verifier() -> webauthn.LocalDevelopmentWebAuthnVerifier:
    return webauthn.LocalDevelopmentWebAuthnVerifier(environment="dev")


def test_webauthn_registration_and_mfa_authentication_contracts() -> None:
    registration_states = webauthn.InMemoryWebAuthnRegistrationStateRepository()
    authentication_states = webauthn.InMemoryWebAuthnAuthenticationStateRepository()
    credentials = webauthn.InMemoryWebAuthnCredentialRepository()
    challenge_store = InMemoryMFAChallengeStore()
    session = Session.create(
        subject_id="user-1",
        tenant_id="tenant-1",
        client_id="client-1",
        requested_scopes={"openid"},
        ttl_seconds=300,
    )

    registration = webauthn.begin_registration(
        session=session,
        user_name="user-1@example.com",
        rp_id="example.com",
        rp_name="Example",
        state_repository=registration_states,
    )
    credential = webauthn.finish_registration(
        state_id=registration.state.state_id,
        credential_id="cred-1",
        public_key="public-key",
        transports=("internal",),
        sign_count=1,
        credential_repository=credentials,
        state_repository=registration_states,
        verifier=_dev_verifier(),
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
    authn = webauthn.begin_authentication_for_mfa(
        session=session,
        mfa_challenge_id=mfa_challenge.challenge_id,
        credential_repository=credentials,
        state_repository=authentication_states,
    )
    verified = webauthn.finish_authentication_for_mfa(
        state_id=authn.state.state_id,
        session=session,
        credential_id="cred-1",
        new_sign_count=2,
        credential_repository=credentials,
        state_repository=authentication_states,
        challenge_store=challenge_store,
        verifier=_dev_verifier(),
    )
    assert verified.verified_at is not None
    assert authentication_states.get(authn.state.state_id) is None


def test_webauthn_sql_repositories_roundtrip() -> None:
    dsn = ":memory:"
    credentials = webauthn.SQLWebAuthnCredentialRepository(dsn)
    registration_states = webauthn.SQLWebAuthnRegistrationStateRepository(dsn)
    authentication_states = webauthn.SQLWebAuthnAuthenticationStateRepository(dsn)
    challenge_store = InMemoryMFAChallengeStore()
    session = Session.create(
        subject_id="user-1",
        tenant_id="tenant-1",
        client_id="client-1",
        requested_scopes={"openid"},
        ttl_seconds=300,
    )

    registration = webauthn.begin_registration(
        session=session,
        user_name="user-1@example.com",
        rp_id="example.com",
        rp_name="Example",
        state_repository=registration_states,
    )
    credential = webauthn.finish_registration(
        state_id=registration.state.state_id,
        credential_id="cred-sql-1",
        public_key="public-key",
        transports=("internal",),
        sign_count=1,
        credential_repository=credentials,
        state_repository=registration_states,
        verifier=_dev_verifier(),
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
    authn = webauthn.begin_authentication_for_mfa(
        session=session,
        mfa_challenge_id=mfa_challenge.challenge_id,
        credential_repository=credentials,
        state_repository=authentication_states,
    )
    verified = webauthn.finish_authentication_for_mfa(
        state_id=authn.state.state_id,
        session=session,
        credential_id="cred-sql-1",
        new_sign_count=3,
        credential_repository=credentials,
        state_repository=authentication_states,
        challenge_store=challenge_store,
        verifier=_dev_verifier(),
    )
    assert verified.verified_at is not None
    persisted = credentials.get("cred-sql-1")
    assert persisted is not None
    assert persisted.sign_count == 3
    assert authentication_states.get(authn.state.state_id) is None


@pytest.mark.asyncio
async def test_webauthn_async_sql_repositories_roundtrip() -> None:
    credentials = webauthn.AsyncSQLWebAuthnCredentialRepository(":memory:")
    registration_states = webauthn.AsyncSQLWebAuthnRegistrationStateRepository(":memory:")
    authentication_states = webauthn.AsyncSQLWebAuthnAuthenticationStateRepository(":memory:")

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
    registration = webauthn.begin_registration(
        session=session,
        user_name="user-async@example.com",
        rp_id="example.com",
        rp_name="Example",
        state_repository=webauthn.InMemoryWebAuthnRegistrationStateRepository(),
    )
    await registration_states.save(registration.state)
    loaded_registration = await registration_states.get(registration.state.state_id)
    assert loaded_registration is not None
    await registration_states.delete(registration.state.state_id)
    assert await registration_states.get(registration.state.state_id) is None

    credential = webauthn.WebAuthnCredential(
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

    auth_state = webauthn.WebAuthnAuthenticationState.issue(
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
    registration_states = webauthn.InMemoryWebAuthnRegistrationStateRepository()
    credentials = webauthn.InMemoryWebAuthnCredentialRepository()
    session = Session.create(
        subject_id="user-1",
        tenant_id="tenant-1",
        client_id="client-1",
        requested_scopes={"openid"},
        ttl_seconds=300,
    )
    registration = webauthn.begin_registration(
        session=session,
        user_name="user-1@example.com",
        rp_id="example.com",
        rp_name="Example",
        state_repository=registration_states,
        ttl_seconds=1,
    )
    registration.state.expires_at = datetime.now(tz=UTC) - timedelta(seconds=1)
    registration_states.save(registration.state)

    with pytest.raises(webauthn.WebAuthnError):
        webauthn.finish_registration(
            state_id=registration.state.state_id,
            credential_id="cred-expired",
            public_key="public-key",
            transports=("internal",),
            sign_count=1,
            credential_repository=credentials,
            state_repository=registration_states,
        )


@pytest.mark.parametrize("new_sign_count", [4, 5])
def test_webauthn_rejects_non_advanced_sign_count(new_sign_count: int) -> None:
    registration_states = webauthn.InMemoryWebAuthnRegistrationStateRepository()
    authentication_states = webauthn.InMemoryWebAuthnAuthenticationStateRepository()
    credentials = webauthn.InMemoryWebAuthnCredentialRepository()
    challenge_store = InMemoryMFAChallengeStore()
    session = Session.create(
        subject_id="user-1",
        tenant_id="tenant-1",
        client_id="client-1",
        requested_scopes={"openid"},
        ttl_seconds=300,
    )
    registration = webauthn.begin_registration(
        session=session,
        user_name="user-1@example.com",
        rp_id="example.com",
        rp_name="Example",
        state_repository=registration_states,
    )
    webauthn.finish_registration(
        state_id=registration.state.state_id,
        credential_id="cred-1",
        public_key="public-key",
        transports=("internal",),
        sign_count=5,
        credential_repository=credentials,
        state_repository=registration_states,
        verifier=_dev_verifier(),
    )
    mfa_challenge = create_mfa_challenge(
        session=session,
        factor_type=MFAFactorType.WEBAUTHN,
        challenge_store=challenge_store,
        required_acr=2,
        purpose="step_up",
        ttl_seconds=120,
    )
    authn = webauthn.begin_authentication_for_mfa(
        session=session,
        mfa_challenge_id=mfa_challenge.challenge_id,
        credential_repository=credentials,
        state_repository=authentication_states,
    )

    with pytest.raises(webauthn.WebAuthnVerificationError):
        webauthn.finish_authentication_for_mfa(
            state_id=authn.state.state_id,
            session=session,
            credential_id="cred-1",
            new_sign_count=new_sign_count,
            credential_repository=credentials,
            state_repository=authentication_states,
            challenge_store=challenge_store,
            verifier=_dev_verifier(),
        )


def test_webauthn_allows_zero_counter_authenticators() -> None:
    registration_states = webauthn.InMemoryWebAuthnRegistrationStateRepository()
    authentication_states = webauthn.InMemoryWebAuthnAuthenticationStateRepository()
    credentials = webauthn.InMemoryWebAuthnCredentialRepository()
    challenge_store = InMemoryMFAChallengeStore()
    session = Session.create(
        subject_id="user-zero",
        tenant_id="tenant-1",
        client_id="client-1",
        requested_scopes={"openid"},
        ttl_seconds=300,
    )
    registration = webauthn.begin_registration(
        session=session,
        user_name="user-zero@example.com",
        rp_id="example.com",
        rp_name="Example",
        state_repository=registration_states,
    )
    webauthn.finish_registration(
        state_id=registration.state.state_id,
        credential_id="cred-zero",
        public_key="public-key",
        transports=("internal",),
        sign_count=0,
        credential_repository=credentials,
        state_repository=registration_states,
        verifier=_dev_verifier(),
    )
    challenge = create_mfa_challenge(
        session=session,
        factor_type=MFAFactorType.WEBAUTHN,
        challenge_store=challenge_store,
        required_acr=2,
        purpose="step_up",
        ttl_seconds=120,
    )
    authn = webauthn.begin_authentication_for_mfa(
        session=session,
        mfa_challenge_id=challenge.challenge_id,
        credential_repository=credentials,
        state_repository=authentication_states,
    )

    verified = webauthn.finish_authentication_for_mfa(
        state_id=authn.state.state_id,
        session=session,
        credential_id="cred-zero",
        new_sign_count=0,
        credential_repository=credentials,
        state_repository=authentication_states,
        challenge_store=challenge_store,
        verifier=_dev_verifier(),
    )

    assert verified.verified_at is not None


def test_webauthn_rejects_replayed_authentication_state() -> None:
    registration_states = webauthn.InMemoryWebAuthnRegistrationStateRepository()
    authentication_states = webauthn.InMemoryWebAuthnAuthenticationStateRepository()
    credentials = webauthn.InMemoryWebAuthnCredentialRepository()
    challenge_store = InMemoryMFAChallengeStore()
    session = Session.create(
        subject_id="user-1",
        tenant_id="tenant-1",
        client_id="client-1",
        requested_scopes={"openid"},
        ttl_seconds=300,
    )
    registration = webauthn.begin_registration(
        session=session,
        user_name="user-1@example.com",
        rp_id="example.com",
        rp_name="Example",
        state_repository=registration_states,
    )
    webauthn.finish_registration(
        state_id=registration.state.state_id,
        credential_id="cred-replay",
        public_key="public-key",
        transports=("internal",),
        sign_count=1,
        credential_repository=credentials,
        state_repository=registration_states,
        verifier=_dev_verifier(),
    )
    challenge = create_mfa_challenge(
        session=session,
        factor_type=MFAFactorType.WEBAUTHN,
        challenge_store=challenge_store,
        required_acr=2,
        purpose="step_up",
        ttl_seconds=120,
    )
    authn = webauthn.begin_authentication_for_mfa(
        session=session,
        mfa_challenge_id=challenge.challenge_id,
        credential_repository=credentials,
        state_repository=authentication_states,
    )
    first = webauthn.finish_authentication_for_mfa(
        state_id=authn.state.state_id,
        session=session,
        credential_id="cred-replay",
        new_sign_count=2,
        credential_repository=credentials,
        state_repository=authentication_states,
        challenge_store=challenge_store,
        verifier=_dev_verifier(),
    )
    assert first.verified_at is not None

    with pytest.raises(webauthn.WebAuthnError):
        webauthn.finish_authentication_for_mfa(
            state_id=authn.state.state_id,
            session=session,
            credential_id="cred-replay",
            new_sign_count=3,
            credential_repository=credentials,
            state_repository=authentication_states,
            challenge_store=challenge_store,
            verifier=_dev_verifier(),
        )


def test_webauthn_production_verifier_rejects_non_advanced_sign_count() -> None:
    verifier = webauthn.ProductionBaselineWebAuthnVerifier()
    state = webauthn.WebAuthnAuthenticationState.issue(
        mfa_challenge_id="challenge-1",
        session_id="session-1",
        subject_id="user-1",
        tenant_id="tenant-1",
        challenge="challenge",
        ttl_seconds=300,
    )
    credential = webauthn.WebAuthnCredential(
        credential_id="cred-1",
        subject_id="user-1",
        tenant_id="tenant-1",
        public_key="public-key",
        sign_count=5,
        transports=("internal",),
        created_at=state.created_at,
    )

    with pytest.raises(webauthn.WebAuthnVerificationError):
        verifier.verify_authentication(
            state=state,
            credential=credential,
            new_sign_count=5,
        )


def test_webauthn_production_verifier_rejects_empty_registration_material() -> None:
    verifier = webauthn.ProductionBaselineWebAuthnVerifier()
    session = Session.create(
        subject_id="user-1",
        tenant_id="tenant-1",
        client_id="client-1",
        requested_scopes={"openid"},
        ttl_seconds=300,
    )
    state = webauthn.WebAuthnRegistrationState.issue(
        session_id=session.session_id,
        subject_id=session.subject_id,
        tenant_id=session.tenant_id,
        challenge="challenge",
        user_name="user-1@example.com",
        ttl_seconds=300,
    )

    with pytest.raises(webauthn.WebAuthnVerificationError):
        verifier.verify_registration(
            state=state,
            credential_id="",
            public_key="public-key",
            transports=("internal",),
            sign_count=1,
        )


def test_build_default_webauthn_verifier_prefers_optional_library(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_module = _FakeWebAuthnModule("webauthn")
    monkeypatch.setitem(sys.modules, "webauthn", fake_module)

    verifier = webauthn.build_default_webauthn_verifier()

    assert isinstance(verifier, webauthn.PyWebAuthnVerifier)


def test_finish_registration_without_verifier_uses_secure_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class RejectingDefaultVerifier:
        def verify_registration(self, **_: object) -> None:
            raise webauthn.WebAuthnVerificationError("default_registration_verifier_called")

    registration_states = webauthn.InMemoryWebAuthnRegistrationStateRepository()
    credentials = webauthn.InMemoryWebAuthnCredentialRepository()
    session = Session.create(
        subject_id="user-default",
        tenant_id="tenant-1",
        client_id="client-1",
        requested_scopes={"openid"},
        ttl_seconds=300,
    )
    registration = webauthn.begin_registration(
        session=session,
        user_name="user-default@example.com",
        rp_id="example.com",
        rp_name="Example",
        state_repository=registration_states,
    )
    monkeypatch.setattr(
        webauthn_services,
        "build_default_webauthn_verifier",
        lambda: RejectingDefaultVerifier(),
    )

    with pytest.raises(
        webauthn.WebAuthnVerificationError,
        match="default_registration_verifier_called",
    ):
        webauthn.finish_registration(
            state_id=registration.state.state_id,
            credential_id="cred-default",
            public_key="public-key",
            transports=("internal",),
            sign_count=1,
            credential_repository=credentials,
            state_repository=registration_states,
        )


def test_finish_authentication_without_verifier_uses_secure_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class RejectingDefaultVerifier:
        def verify_authentication(self, **_: object) -> None:
            raise webauthn.WebAuthnVerificationError("default_authentication_verifier_called")

    authentication_states = webauthn.InMemoryWebAuthnAuthenticationStateRepository()
    credentials = webauthn.InMemoryWebAuthnCredentialRepository()
    challenge_store = InMemoryMFAChallengeStore()
    session = Session.create(
        subject_id="user-default",
        tenant_id="tenant-1",
        client_id="client-1",
        requested_scopes={"openid"},
        ttl_seconds=300,
    )
    credential = webauthn.WebAuthnCredential(
        credential_id="cred-default",
        subject_id=session.subject_id,
        tenant_id=session.tenant_id,
        public_key="public-key",
        sign_count=1,
        transports=("internal",),
        created_at=datetime.now(tz=UTC),
    )
    credentials.save(credential)
    challenge = create_mfa_challenge(
        session=session,
        factor_type=MFAFactorType.WEBAUTHN,
        challenge_store=challenge_store,
        required_acr=2,
        purpose="step_up",
        ttl_seconds=120,
    )
    authn = webauthn.begin_authentication_for_mfa(
        session=session,
        mfa_challenge_id=challenge.challenge_id,
        credential_repository=credentials,
        state_repository=authentication_states,
    )
    monkeypatch.setattr(
        webauthn_services,
        "build_default_webauthn_verifier",
        lambda: RejectingDefaultVerifier(),
    )

    with pytest.raises(
        webauthn.WebAuthnVerificationError,
        match="default_authentication_verifier_called",
    ):
        webauthn.finish_authentication_for_mfa(
            state_id=authn.state.state_id,
            session=session,
            credential_id=credential.credential_id,
            new_sign_count=2,
            credential_repository=credentials,
            state_repository=authentication_states,
            challenge_store=challenge_store,
        )


def test_default_finish_registration_rejects_missing_ceremony_response() -> None:
    registration_states = webauthn.InMemoryWebAuthnRegistrationStateRepository()
    credentials = webauthn.InMemoryWebAuthnCredentialRepository()
    session = Session.create(
        subject_id="user-default",
        tenant_id="tenant-1",
        client_id="client-1",
        requested_scopes={"openid"},
        ttl_seconds=300,
    )
    registration = webauthn.begin_registration(
        session=session,
        user_name="user-default@example.com",
        rp_id="example.com",
        rp_name="Example",
        state_repository=registration_states,
    )

    with pytest.raises(
        webauthn.WebAuthnVerificationError,
        match="webauthn_registration_response_required",
    ):
        webauthn.finish_registration(
            state_id=registration.state.state_id,
            credential_id="cred-default",
            public_key="public-key",
            transports=("internal",),
            sign_count=1,
            credential_repository=credentials,
            state_repository=registration_states,
        )


def test_local_development_verifier_requires_explicit_unsafe_context() -> None:
    with pytest.raises(RuntimeError, match="requires_environment_dev_or_allow_insecure"):
        webauthn.LocalDevelopmentWebAuthnVerifier()

    with pytest.raises(RuntimeError, match="forbidden_in_production"):
        webauthn.LocalDevelopmentWebAuthnVerifier(environment="prod", allow_insecure=True)

    assert isinstance(_dev_verifier(), webauthn.LocalDevelopmentWebAuthnVerifier)
    assert isinstance(
        webauthn.LocalDevelopmentWebAuthnVerifier(allow_insecure=True),
        webauthn.LocalDevelopmentWebAuthnVerifier,
    )


def test_py_webauthn_verifier_requires_full_responses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_module = _FakeWebAuthnModule("webauthn")
    monkeypatch.setitem(sys.modules, "webauthn", fake_module)

    verifier = webauthn.PyWebAuthnVerifier()
    registration_state = webauthn.WebAuthnRegistrationState.issue(
        session_id="session-1",
        subject_id="user-1",
        tenant_id="tenant-1",
        challenge="challenge-registration",
        user_name="user-1@example.com",
        ttl_seconds=300,
    )
    authentication_state = webauthn.WebAuthnAuthenticationState.issue(
        mfa_challenge_id="challenge-1",
        session_id="session-1",
        subject_id="user-1",
        tenant_id="tenant-1",
        challenge="challenge-authentication",
        ttl_seconds=300,
    )
    credential = webauthn.WebAuthnCredential(
        credential_id="cred-1",
        subject_id="user-1",
        tenant_id="tenant-1",
        public_key="public-key",
        sign_count=1,
        transports=("internal",),
        created_at=registration_state.created_at,
    )

    with pytest.raises(webauthn.WebAuthnVerificationError):
        verifier.verify_registration(
            state=registration_state,
            credential_id="cred-1",
            public_key="public-key",
            transports=("internal",),
            sign_count=1,
        )

    verifier.verify_registration(
        state=registration_state,
        credential_id="cred-1",
        public_key="public-key",
        transports=("internal",),
        sign_count=1,
        credential_response=json.dumps({"id": "cred-1"}),
        expected_origin="https://example.com",
        rp_id="example.com",
    )

    with pytest.raises(webauthn.WebAuthnVerificationError):
        verifier.verify_authentication(
            state=authentication_state,
            credential=credential,
            new_sign_count=2,
        )

    verifier.verify_authentication(
        state=authentication_state,
        credential=credential,
        new_sign_count=2,
        authentication_response=json.dumps({"id": "cred-1"}),
        expected_origin="https://example.com",
        rp_id="example.com",
    )
