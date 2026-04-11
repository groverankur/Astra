# mypy: disable-error-code="misc"

import pytest
from astraauth_core.config.settings import AuthConfig
from astraauth_core.events.inmemory import InMemoryEventBus
from astraauth_core.mfa import (
    InMemoryMFAChallengeStore,
    MFAChallengeStateError,
    MFAFactorType,
    create_mfa_challenge,
    upgrade_session_with_verified_challenge,
    verify_mfa_challenge,
)
from astraauth_core.sessions.introspection import (
    introspect_access_token,
    introspect_refresh_token,
)
from astraauth_core.sessions.models import Session
from astraauth_core.sessions.services import issue_session_and_refresh_token
from astraauth_core.sessions.store import InMemorySessionStore
from astraauth_core.token.token_manager import TokenKeyManager


def test_mfa_challenge_verification_and_session_upgrade() -> None:
    session_store = InMemorySessionStore()
    challenge_store = InMemoryMFAChallengeStore()
    bus = InMemoryEventBus()
    seen: list[tuple[str, dict[str, object]]] = []
    token_manager = TokenKeyManager(AuthConfig())

    for topic in ["mfa.challenge", "session.upgraded"]:
        bus.subscribe(topic, lambda payload, t=topic: seen.append((t, payload)))

    session, refresh_token = issue_session_and_refresh_token(
        subject_id="user-1",
        client_id="client-1",
        tenant_id="tenant-1",
        requested_scopes={"openid"},
        session_store=session_store,
        token_manager=token_manager,
        session_ttl_seconds=300,
    )

    challenge = create_mfa_challenge(
        session=session,
        factor_type=MFAFactorType.TOTP,
        challenge_store=challenge_store,
        required_acr=2,
        purpose="step_up",
        ttl_seconds=120,
        event_bus=bus,
    )
    verified = verify_mfa_challenge(
        challenge_id=challenge.challenge_id,
        challenge_store=challenge_store,
        session=session,
    )
    upgraded = upgrade_session_with_verified_challenge(
        challenge_id=challenge.challenge_id,
        challenge_store=challenge_store,
        session_store=session_store,
        methods={"totp"},
        event_bus=bus,
    )

    assert verified.verified_at is not None
    assert upgraded.acr == 2
    assert set(upgraded.amr) == {"totp"}
    assert upgraded.version == 2
    assert upgraded.upgraded_at is not None

    refresh_info = introspect_refresh_token(
        refresh_token,
        token_manager=token_manager,
        session_store=session_store,
    )
    assert refresh_info["active"] is True
    assert refresh_info["acr"] == 2
    assert refresh_info["amr"] == ["totp"]

    access_token = token_manager.issue_jwt(
        subject=upgraded.subject_id,
        audience="api",
        extra_claims={
            "sid": upgraded.session_id,
            "tid": upgraded.tenant_id,
            "ver": upgraded.version,
            "acr": upgraded.acr,
            "amr": list(upgraded.amr),
        },
    )
    access_info = introspect_access_token(
        access_token,
        token_manager=token_manager,
        expected_audience="api",
        session_store=session_store,
    )
    assert access_info["active"] is True
    assert access_info["acr"] == 2
    assert access_info["amr"] == ["totp"]

    topics = [topic for topic, _ in seen]
    assert "mfa.challenge" in topics
    assert "session.upgraded" in topics



def test_session_upgrade_requires_verified_challenge() -> None:
    session_store = InMemorySessionStore()
    challenge_store = InMemoryMFAChallengeStore()
    session = Session.create(
        subject_id="user-1",
        tenant_id="tenant-1",
        client_id="client-1",
        requested_scopes={"openid"},
        ttl_seconds=300,
    )
    session_store.save(session)

    challenge = create_mfa_challenge(
        session=session,
        factor_type=MFAFactorType.EMAIL_OTP,
        challenge_store=challenge_store,
        required_acr=2,
        purpose="step_up",
        ttl_seconds=120,
    )

    with pytest.raises(MFAChallengeStateError):
        upgrade_session_with_verified_challenge(
            challenge_id=challenge.challenge_id,
            challenge_store=challenge_store,
            session_store=session_store,
            methods={"email_otp"},
        )

