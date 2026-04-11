# mypy: disable-error-code="index"

from astraauth_core.adapters.http_types import NormalizedRequestContext
from astraauth_core.authorization.models import Role
from astraauth_core.mfa import enroll_totp_factor
from astraauth_core.oauth.models import OAuthClient, Subject
from astraauth_core.sessions.services import issue_session_and_refresh_token
from astraauth_service import build_inmemory_service


class FakeTOTPProvider:
    def generate_secret(self) -> str:
        return "BASE32SECRET"

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
        return f"otpauth://totp/{issuer}:{account_name}?secret={secret}"

    def verify(
        self,
        *,
        secret: str,
        code: str,
        digits: int,
        period: int,
        algorithm: str,
    ) -> bool:
        return secret == "BASE32SECRET" and code == "123456"


def test_service_adapter_handles_totp_mfa_challenge_and_verify() -> None:
    svc = build_inmemory_service(default_plugins_enabled=False)
    svc.adapter._totp_provider = FakeTOTPProvider()
    enrollment = enroll_totp_factor(
        subject_id="user-1",
        tenant_id="tenant-1",
        issuer="AstraAuth",
        account_name="user-1@example.com",
        factor_store=svc.totp_factors,
        provider=svc.adapter._totp_provider,
    )
    enrollment.factor.activate()
    svc.totp_factors.save(enrollment.factor)

    session, _ = issue_session_and_refresh_token(
        subject_id="user-1",
        client_id="client-1",
        tenant_id="tenant-1",
        requested_scopes={"openid"},
        session_store=svc.sessions,
        token_manager=svc.token_manager,
        session_ttl_seconds=300,
    )

    challenge_resp = svc.adapter.handle_mfa_challenge(
        NormalizedRequestContext(
            http_method="POST",
            request_path="/mfa/challenge",
            query_params={},
            headers={},
            form_data={
                "session_id": session.session_id,
                "factor_type": "totp",
                "required_acr": "2",
                "purpose": "step_up",
            },
        )
    )
    assert challenge_resp.status == 428
    challenge_id = challenge_resp.body["challenge_id"]

    verify_resp = svc.adapter.handle_mfa_verify(
        NormalizedRequestContext(
            http_method="POST",
            request_path="/mfa/verify",
            query_params={},
            headers={},
            form_data={
                "session_id": session.session_id,
                "challenge_id": challenge_id,
                "factor_type": "totp",
                "code": "123456",
            },
        )
    )
    assert verify_resp.status == 200
    assert verify_resp.body["acr"] == 2
    assert verify_resp.body["amr"] == ["totp"]


def test_service_adapter_handles_email_otp_challenge_and_verify() -> None:
    svc = build_inmemory_service(default_plugins_enabled=False)
    factor_id = svc.enroll_subject_email_otp(
        subject_id="user-1",
        tenant_id="tenant-1",
        email="user-1@example.com",
    )
    svc.activate_subject_email_otp(factor_id=factor_id)

    session, _ = issue_session_and_refresh_token(
        subject_id="user-1",
        client_id="client-1",
        tenant_id="tenant-1",
        requested_scopes={"openid"},
        session_store=svc.sessions,
        token_manager=svc.token_manager,
        session_ttl_seconds=300,
    )

    challenge_resp = svc.adapter.handle_mfa_challenge(
        NormalizedRequestContext(
            http_method="POST",
            request_path="/mfa/challenge",
            query_params={},
            headers={},
            form_data={
                "session_id": session.session_id,
                "factor_type": "email_otp",
                "required_acr": "2",
                "purpose": "step_up",
            },
        )
    )
    assert challenge_resp.status == 428
    code = svc.email_delivery.sent_messages[0]["code"]

    verify_resp = svc.adapter.handle_mfa_verify(
        NormalizedRequestContext(
            http_method="POST",
            request_path="/mfa/verify",
            query_params={},
            headers={},
            form_data={
                "session_id": session.session_id,
                "challenge_id": challenge_resp.body["challenge_id"],
                "factor_type": "email_otp",
                "code": code,
            },
        )
    )
    assert verify_resp.status == 200
    assert verify_resp.body["acr"] == 2
    assert verify_resp.body["amr"] == ["email_otp"]


def test_service_adapter_handles_webauthn_registration_and_step_up() -> None:
    svc = build_inmemory_service(default_plugins_enabled=False)
    subject = Subject(subject_id="user-1", tenants={"tenant-1"}, username="user1")
    svc.add_subject_password(
        subject=subject,
        tenant_id="tenant-1",
        username="user1",
        password="secret",
    )
    svc.add_role(Role(name="user", permissions={"openid"}))
    svc.assign_roles(subject_id="user-1", tenant_id="tenant-1", roles={"user"})
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

    register_start = svc.adapter.handle_webauthn_register_start(
        NormalizedRequestContext(
            http_method="POST",
            request_path="/webauthn/register/start",
            query_params={},
            headers={},
            form_data={
                "session_id": session.session_id,
                "user_name": "user1@example.com",
                "rp_id": "example.com",
                "rp_name": "Example",
            },
        )
    )
    assert register_start.status == 200

    register_finish = svc.adapter.handle_webauthn_register_finish(
        NormalizedRequestContext(
            http_method="POST",
            request_path="/webauthn/register/finish",
            query_params={},
            headers={},
            form_data={
                "state_id": register_start.body["state_id"],
                "credential_id": "cred-1",
                "public_key": "public-key",
                "transports": "internal",
                "sign_count": "1",
            },
        )
    )
    assert register_finish.status == 200

    token_resp = svc.adapter.handle_token(
        NormalizedRequestContext(
            http_method="POST",
            request_path="/token",
            query_params={},
            headers={},
            form_data={
                "grant_type": "password",
                "client_id": "client-1",
                "tenant_id": "tenant-1",
                "username": "user1",
                "password": "secret",
                "scope": "openid",
                "required_acr": "2",
                "preferred_factor_type": "webauthn",
            },
        )
    )
    assert token_resp.status == 428
    assert token_resp.body["factor_type"] == "webauthn"

    finish_auth = svc.adapter.handle_webauthn_authenticate_finish(
        NormalizedRequestContext(
            http_method="POST",
            request_path="/webauthn/authenticate/finish",
            query_params={},
            headers={},
            form_data={
                "session_id": token_resp.body["session_id"],
                "state_id": token_resp.body["state_id"],
                "credential_id": "cred-1",
                "sign_count": "2",
            },
        )
    )
    assert finish_auth.status == 200
    assert finish_auth.body["acr"] == 2
    assert finish_auth.body["amr"] == ["webauthn"]


