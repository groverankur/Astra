from __future__ import annotations

from datetime import UTC, datetime, timedelta

from astraauth.core.events.base import EventBus
from astraauth.core.sessions.models import Session
from astraauth.core.sessions.store import SessionStore
from astraauth.core.token.token_manager import TokenKeyManager


class RefreshTokenError(Exception):
    pass


def issue_session_and_refresh_token(
    *,
    subject_id: str,
    client_id: str,
    tenant_id: str,
    requested_scopes: set[str],
    session_store: SessionStore,
    token_manager: TokenKeyManager,
    session_ttl_seconds: int,
    initial_acr: int = 1,
    initial_amr: set[str] | None = None,
    event_bus: EventBus | None = None,
) -> tuple[Session, str]:
    """
    Create a new session and issue encrypted refresh token.
    """

    now = datetime.now(tz=UTC)
    expires_at = now + timedelta(seconds=session_ttl_seconds)

    session = Session.create(
        subject_id=subject_id,
        tenant_id=tenant_id,
        client_id=client_id,
        requested_scopes=requested_scopes,
        ttl_seconds=session_ttl_seconds,
    )
    session.acr = initial_acr
    session.amr = tuple(sorted(initial_amr or set()))

    session_store.save(session)
    refresh_claims = {
        "iss": token_manager._config.issuer,
        "sub": subject_id,
        "aud": client_id,
        "tid": tenant_id,
        "sid": session.session_id,
        "ver": session.version,
        "acr": session.acr,
        "amr": list(session.amr),
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }

    refresh_token = token_manager.issue_jwe(refresh_claims)
    if event_bus is not None:
        event_bus.publish(
            "session.created",
            {
                "sid": session.session_id,
                "sub": subject_id,
                "tid": tenant_id,
                "cid": client_id,
                "acr": session.acr,
            },
        )
        event_bus.publish(
            "token.issued",
            {"token_type": "refresh_token", "sid": session.session_id, "sub": subject_id},  # nosec B105
        )

    return session, refresh_token


def rotate_refresh_token(
    *,
    refresh_token: str,
    session_store: SessionStore,
    token_manager: TokenKeyManager,
    session_ttl_seconds: int,
    event_bus: EventBus | None = None,
) -> tuple[Session, str]:
    """
    Validate refresh token, rotate session, issue new refresh token.
    """

    claims = token_manager.decrypt_jwe(refresh_token)

    session_id = claims.get("sid")
    version = claims.get("ver")

    if not session_id or not isinstance(version, int):
        raise RefreshTokenError("Invalid refresh token payload")

    session = session_store.get(session_id)
    if not session:
        raise RefreshTokenError("Unknown session")

    if session.revoked:
        raise RefreshTokenError("Session revoked")

    if session.is_expired():
        raise RefreshTokenError("Session expired")

    if session.version != version:
        raise RefreshTokenError("Refresh token replay detected")

    session.version += 1
    session.expires_at = datetime.now(tz=UTC) + timedelta(seconds=session_ttl_seconds)

    session_store.save(session)

    new_claims = {
        "iss": token_manager._config.issuer,
        "sub": session.subject_id,
        "aud": session.client_id,
        "tid": session.tenant_id,
        "sid": session.session_id,
        "ver": session.version,
        "acr": session.acr,
        "amr": list(session.amr),
        "iat": int(datetime.now(tz=UTC).timestamp()),
        "exp": int(session.expires_at.timestamp()),
    }

    new_refresh_token = token_manager.issue_jwe(new_claims)
    if event_bus is not None:
        event_bus.publish(
            "session.rotated",
            {
                "sid": session.session_id,
                "sub": session.subject_id,
                "tid": session.tenant_id,
                "acr": session.acr,
            },
        )
        event_bus.publish(
            "token.issued",
            {"token_type": "refresh_token", "sid": session.session_id, "sub": session.subject_id},  # nosec B105
        )

    return session, new_refresh_token


def logout_by_refresh_token(
    *,
    refresh_token: str,
    session_store: SessionStore,
    token_manager: TokenKeyManager,
    event_bus: EventBus | None = None,
) -> None:
    claims = token_manager.decrypt_jwe(refresh_token)
    session_id = claims.get("sid")

    if not session_id:
        raise RefreshTokenError("Invalid refresh token")

    session_store.revoke(session_id)
    if event_bus is not None:
        event_bus.publish("session.revoked", {"sid": session_id})


def logout_all_for_subject(
    *,
    subject_id: str,
    session_store: SessionStore,
    event_bus: EventBus | None = None,
) -> None:
    session_store.revoke_all_for_subject(subject_id)
    if event_bus is not None:
        event_bus.publish("session.revoked_all", {"sub": subject_id})
