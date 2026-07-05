from astraauth.core.adapters.http_types import HttpResponse, NormalizedRequestContext
from astraauth.core.authorization.models import Role
from astraauth.core.mfa import enroll_totp_factor
from astraauth.core.oauth.models import OAuthClient, Subject
from astraauth.core.sessions.services import issue_session_and_refresh_token
from astraauth.service import build_inmemory_service
from astraauth.webauthn import LocalDevelopmentWebAuthnVerifier


def _body(response: HttpResponse) -> dict[str, object]:
    body = response.body
    assert isinstance(body, dict)
    return body


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
    challenge_id = str(_body(challenge_resp)["challenge_id"])

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
    verify_body = _body(verify_resp)
    assert verify_body["acr"] == 2
    assert verify_body["amr"] == ["totp"]


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
    challenge_body = _body(challenge_resp)

    verify_resp = svc.adapter.handle_mfa_verify(
        NormalizedRequestContext(
            http_method="POST",
            request_path="/mfa/verify",
            query_params={},
            headers={},
            form_data={
                "session_id": session.session_id,
                "challenge_id": str(challenge_body["challenge_id"]),
                "factor_type": "email_otp",
                "code": code,
            },
        )
    )
    assert verify_resp.status == 200
    verify_body = _body(verify_resp)
    assert verify_body["acr"] == 2
    assert verify_body["amr"] == ["email_otp"]


def test_service_adapter_throttles_repeated_mfa_verification_failures() -> None:
    svc = build_inmemory_service(default_plugins_enabled=False)
    svc.adapter._mfa_verify_throttle_max_events = 1
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
            client_ip="127.0.0.1",
        )
    )
    challenge_body = _body(challenge_resp)

    bad_req = NormalizedRequestContext(
        http_method="POST",
        request_path="/mfa/verify",
        query_params={},
        headers={},
        form_data={
            "session_id": session.session_id,
            "challenge_id": str(challenge_body["challenge_id"]),
            "factor_type": "email_otp",
            "code": "000000",
        },
        client_ip="127.0.0.1",
    )
    first = svc.adapter.handle_mfa_verify(bad_req)
    second = svc.adapter.handle_mfa_verify(bad_req)
    third = svc.adapter.handle_mfa_verify(bad_req)
    assert first.status == 400
    assert second.status == 400
    assert third.status == 429
    assert third.headers is not None
    assert int(third.headers["Retry-After"]) >= 1


def test_service_adapter_handles_webauthn_registration_and_step_up() -> None:
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
    register_start_body = _body(register_start)

    register_finish = svc.adapter.handle_webauthn_register_finish(
        NormalizedRequestContext(
            http_method="POST",
            request_path="/webauthn/register/finish",
            query_params={},
            headers={},
            form_data={
                "state_id": str(register_start_body["state_id"]),
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
    token_body = _body(token_resp)
    assert token_body["factor_type"] == "webauthn"

    finish_auth = svc.adapter.handle_webauthn_authenticate_finish(
        NormalizedRequestContext(
            http_method="POST",
            request_path="/webauthn/authenticate/finish",
            query_params={},
            headers={},
            form_data={
                "session_id": str(token_body["session_id"]),
                "state_id": str(token_body["state_id"]),
                "credential_id": "cred-1",
                "sign_count": "2",
            },
        )
    )
    assert finish_auth.status == 200
    finish_body = _body(finish_auth)
    assert finish_body["acr"] == 2
    assert finish_body["amr"] == ["webauthn"]
