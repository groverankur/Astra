from typing import Any

from astraauth_core.sessions.store import SessionStore
from astraauth_core.token.token_manager import TokenKeyManager


def introspect_refresh_token(
    token: str,
    *,
    token_manager: TokenKeyManager,
    session_store: SessionStore,
) -> dict[str, Any]:
    try:
        claims = token_manager.decrypt_jwe(token)
    except Exception:
        return {"active": False}

    session_id = claims.get("sid")
    if not session_id:
        return {"active": False}

    session = session_store.get(session_id)
    if not session or session.revoked or session.is_expired():
        return {"active": False}

    return {
        "active": True,
        "sub": session.subject_id,
        "client_id": session.client_id,
        "sid": session.session_id,
        "exp": int(session.expires_at.timestamp()),
        "tid": session.tenant_id,
        "acr": session.acr,
        "amr": list(session.amr),
    }



def introspect_access_token(
    token: str,
    *,
    token_manager: TokenKeyManager,
    expected_audience: str,
    session_store: SessionStore,
) -> dict[str, Any]:
    try:
        claims = token_manager.verify_jwt(
            token,
            audience=expected_audience,
        )
    except Exception:
        return {"active": False}

    sid = claims.get("sid")
    tenant_id = claims.get("tid")
    version = claims.get("ver")
    session = None

    if sid is not None:
        if not isinstance(tenant_id, str) or not tenant_id:
            return {"active": False}

        session = session_store.get(sid)

        if not session:
            return {"active": False}

        if session.tenant_id != tenant_id:
            return {"active": False}

        if session.revoked:
            return {"active": False}

        if session.is_expired():
            return {"active": False}

        if not isinstance(version, int) or session.version != version:
            return {"active": False}

    return {
        "active": True,
        "sub": claims.get("sub"),
        "aud": claims.get("aud"),
        "scope": claims.get("scp"),
        "exp": claims.get("exp"),
        "sid": sid,
        "tid": tenant_id,
        "acr": claims.get("acr", session.acr if session is not None else None),
        "amr": claims.get("amr", list(session.amr) if session is not None else []),
    }
