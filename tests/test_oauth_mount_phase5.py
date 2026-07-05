from fastapi import FastAPI
from fastapi.testclient import TestClient

from astraauth.adapters.fastapi.wiring import mount_oauth
from astraauth.adapters.origin import AdapterOriginPolicy
from astraauth.core.oauth.models import OAuthClient, Subject
from astraauth.core.sessions.services import issue_session_and_refresh_token
from astraauth.service import build_inmemory_service
from astraauth.webauthn import LocalDevelopmentWebAuthnVerifier


def test_mount_oauth_exposes_mfa_and_webauthn_routes() -> None:
    app = FastAPI()
    svc = build_inmemory_service(
        default_plugins_enabled=False,
        webauthn_verifier=LocalDevelopmentWebAuthnVerifier(environment="dev"),
    )
    subject = Subject(subject_id="user-1", tenants={"tenant-1"}, username="user1")
    svc.add_subject_password(
        subject=subject,
        tenant_id="tenant-1",
        username="user1",
        password="secret",
    )
    svc.add_client(
        OAuthClient(
            client_id="client-1",
            redirect_uris={"https://client.local/callback"},
            allowed_scopes={"openid"},
            client_type="public",
            auth_method="none",
            require_pkce=False,
        )
    )
    session, _ = issue_session_and_refresh_token(
        subject_id="user-1",
        client_id="client-1",
        tenant_id="tenant-1",
        requested_scopes={"openid"},
        session_store=svc.sessions,
        token_manager=svc.token_manager,
        session_ttl_seconds=300,
    )

    mount_oauth(app, svc.adapter)
    client = TestClient(app)

    register_start = client.post(
        "/webauthn/register/start",
        data={
            "session_id": session.session_id,
            "user_name": "user1@example.com",
            "rp_id": "example.com",
            "rp_name": "Example",
        },
    )
    assert register_start.status_code == 200
    assert register_start.headers["x-frame-options"] == "DENY"
    assert register_start.headers["x-content-type-options"] == "nosniff"
    assert register_start.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in register_start.headers["content-security-policy"]

    register_finish = client.post(
        "/webauthn/register/finish",
        data={
            "state_id": register_start.json()["state_id"],
            "credential_id": "cred-1",
            "public_key": "public-key",
            "transports": "internal",
            "sign_count": "1",
        },
    )
    assert register_finish.status_code == 200

    challenge = client.post(
        "/mfa/challenge",
        data={
            "session_id": session.session_id,
            "factor_type": "webauthn",
            "required_acr": "2",
        },
    )
    assert challenge.status_code == 428
    assert challenge.headers["cache-control"] == "no-store"


def test_fastapi_origin_policy_rejects_disallowed_state_changing_origin() -> None:
    app = FastAPI()
    svc = build_inmemory_service(default_plugins_enabled=False)
    mount_oauth(
        app,
        svc.adapter,
        origin_policy=AdapterOriginPolicy(allowed_origins=frozenset({"https://app.example.com"})),
    )
    client = TestClient(app)

    rejected = client.post("/token", headers={"Origin": "https://evil.example.com"}, data={})
    allowed = client.options(
        "/token",
        headers={
            "Origin": "https://app.example.com",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert rejected.status_code == 403
    assert rejected.json()["error"] == "origin_not_allowed"
    assert allowed.status_code == 204
    assert allowed.headers["access-control-allow-origin"] == "https://app.example.com"
