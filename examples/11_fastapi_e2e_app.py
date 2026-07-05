"""Developer reference FastAPI app for Astra's integrated feature surface.

This example is intentionally local-friendly and includes demo-only credentials,
mock OIDC provider behavior, and simplified WebAuthn material. It is useful as
an end-to-end reference for library users, but it should not be deployed
unchanged as a production application.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict
from os import getenv
from typing import Any
from urllib.parse import parse_qs, urlparse

from fastapi import FastAPI

from astraauth.adapters import AdapterOriginPolicy
from astraauth.adapters.extensions import mount_plugin_endpoints_fastapi
from astraauth.adapters.fastapi.wiring import mount_oauth
from astraauth.core.adapters.http_types import NormalizedRequestContext
from astraauth.core.authorization.models import Role
from astraauth.core.oauth.models import OAuthClient, Subject
from astraauth.idp import (
    ClaimAttributeMapping,
    GroupRoleMapping,
    OIDCIDTokenClaims,
    OIDCProviderConfig,
    OIDCTokenResponse,
    OIDCUserInfo,
)
from astraauth.plugins.contracts import EndpointExtension, HookName
from astraauth.service import AstraAuthService, build_inmemory_service

APP_BASE_URL = getenv("ASTRAAUTH_EXAMPLE_BASE_URL", "http://127.0.0.1:8000")
TENANT_ID = "tenant-1"
CLIENT_ID = "client-1"
USERNAME = "alice"
PASSWORD = "local-demo-password-change-before-sharing"
API_KEY = "local-demo-api-key-change-before-sharing"
OIDC_PROVIDER_ID = "demo-oidc"


class DemoMetadataClient:
    def fetch_metadata(self, *, discovery_url: str) -> dict[str, object]:
        _ = discovery_url
        provider_base = f"{APP_BASE_URL}/demo/idp"
        return {
            "issuer": provider_base,
            "authorization_endpoint": f"{provider_base}/authorize",
            "token_endpoint": f"{provider_base}/token",
            "jwks_uri": f"{provider_base}/jwks",
            "userinfo_endpoint": f"{provider_base}/userinfo",
        }


class DemoExchangeClient:
    def exchange_code(
        self,
        *,
        provider: OIDCProviderConfig,
        metadata: object,
        code: str,
        redirect_uri: str,
        code_verifier: str,
    ) -> OIDCTokenResponse:
        _ = (provider, metadata, redirect_uri, code_verifier)
        assert code == "demo-auth-code"
        return OIDCTokenResponse(
            access_token="demo-external-access-token",
            token_type="Bearer",
            id_token="demo-id-token",
        )

    def validate_id_token(
        self,
        *,
        provider: OIDCProviderConfig,
        metadata: object,
        token_response: OIDCTokenResponse,
        expected_nonce: str,
    ) -> OIDCIDTokenClaims:
        _ = (provider, metadata, token_response)
        return OIDCIDTokenClaims(
            issuer=f"{APP_BASE_URL}/demo/idp",
            subject="external-user-1",
            audience=("demo-external-client",),
            nonce=expected_nonce,
        )

    def fetch_userinfo(
        self,
        *,
        provider: OIDCProviderConfig,
        metadata: object,
        token_response: OIDCTokenResponse,
    ) -> OIDCUserInfo:
        _ = (provider, metadata, token_response)
        return OIDCUserInfo(
            subject="external-user-1",
            email="alice@example.com",
            email_verified=True,
            claims={"groups": ("admins",), "department": "Platform"},
        )


class DemoRuntimePlugin:
    name = "demo"
    order = 10

    def hooks(self) -> Mapping[HookName, Any]:
        return {
            "auth.post_authenticate": lambda payload: {
                "plugin_demo_seen": True,
                "plugin_demo_tenant": payload.get("tenant_id"),
            },
            "token.issued": lambda payload: {
                "plugin_demo_last_token_type": payload.get("token_type")
            },
        }

    def register_endpoints(self) -> Sequence[EndpointExtension]:
        return (
            EndpointExtension(
                plugin_name=self.name,
                path="/auth/ext/demo/runtime",
                methods=("GET",),
                handler=lambda payload: {
                    "plugin": self.name,
                    "path": payload["path"],
                    "method": payload["method"],
                    "query": payload["query"],
                },
            ),
        )

    def register_tables(self) -> Sequence[Any]:
        return ()

    def register_columns(self) -> Sequence[Any]:
        return ()


def _request(
    *,
    method: str,
    path: str,
    form_data: Mapping[str, str] | None = None,
    query_params: Mapping[str, str] | None = None,
) -> NormalizedRequestContext:
    return NormalizedRequestContext(
        http_method=method,
        request_path=path,
        query_params=dict(query_params or {}),
        headers={},
        form_data=dict(form_data or {}),
    )


def _seed_service() -> AstraAuthService:
    service = build_inmemory_service(default_plugins_enabled=True)

    subject = Subject(
        subject_id="user-1",
        tenants={TENANT_ID},
        username=USERNAME,
    )
    service.add_subject_password(
        subject=subject,
        tenant_id=TENANT_ID,
        username=USERNAME,
        password=PASSWORD,
    )
    service.add_subject_api_key(
        subject=subject,
        tenant_id=TENANT_ID,
        label="demo-key",
        api_key_plaintext=API_KEY,
    )
    service.add_role(Role(name="user", permissions={"openid"}))
    service.add_role(Role(name="admin", permissions={"openid"}))
    service.assign_roles(subject_id=subject.subject_id, tenant_id=TENANT_ID, roles={"user"})
    service.add_client(
        OAuthClient(
            client_id=CLIENT_ID,
            redirect_uris={f"{APP_BASE_URL}/oidc/callback"},
            allowed_scopes={"openid"},
            allowed_tenants={TENANT_ID},
            client_type="public",
            auth_method="none",
            require_pkce=False,
        )
    )

    email_factor_id = service.enroll_subject_email_otp(
        subject_id=subject.subject_id,
        tenant_id=TENANT_ID,
        email="alice@example.com",
    )
    service.activate_subject_email_otp(factor_id=email_factor_id)

    service.register_plugin(DemoRuntimePlugin())
    service.enable_plugin(tenant_id=TENANT_ID, plugin_name="demo")

    service.register_oidc_provider(
        provider=OIDCProviderConfig(
            provider_id=OIDC_PROVIDER_ID,
            issuer=f"{APP_BASE_URL}/demo/idp",
            client_id="demo-external-client",
            client_secret="demo-external-secret",
            discovery_url=f"{APP_BASE_URL}/demo/idp/.well-known/openid-configuration",
        )
    )
    service.add_oidc_group_role_mapping(
        GroupRoleMapping(
            provider_id=OIDC_PROVIDER_ID,
            tenant_id=TENANT_ID,
            external_group="admins",
            role_name="admin",
        )
    )
    service.add_oidc_claim_attribute_mapping(
        ClaimAttributeMapping(
            provider_id=OIDC_PROVIDER_ID,
            tenant_id=TENANT_ID,
            claim_name="department",
            attribute_name="department",
            transform="lower",
        )
    )
    service.oidc_handler._metadata_client = DemoMetadataClient()
    service.oidc_handler._exchange_client = DemoExchangeClient()
    return service


SERVICE = _seed_service()
APP = FastAPI(
    title="Astra FastAPI E2E Example",
    version="0.5.1",
    description="Reference FastAPI app showing Astra OAuth, MFA, WebAuthn, plugins, and OIDC federation together.",
)

ORIGIN_POLICY = AdapterOriginPolicy(
    allowed_origins=frozenset({APP_BASE_URL}),
    allowed_callback_origins=frozenset({APP_BASE_URL}),
)
mount_oauth(APP, SERVICE.adapter, origin_policy=ORIGIN_POLICY)
mount_plugin_endpoints_fastapi(app=APP, runtime=SERVICE.plugin_runtime, tenant_id=TENANT_ID)


def _ensure_webauthn_credential() -> dict[str, object]:
    existing = SERVICE.webauthn_credentials.get("cred-demo")
    if existing is not None:
        return {"credential_id": existing.credential_id, "already_present": True}
    token_resp = SERVICE.adapter.handle_token(
        _request(
            method="POST",
            path="/token",
            form_data={
                "grant_type": "password",
                "client_id": CLIENT_ID,
                "tenant_id": TENANT_ID,
                "username": USERNAME,
                "password": PASSWORD,
                "scope": "openid",
            },
        )
    )
    assert isinstance(token_resp.body, dict)
    register_start = SERVICE.adapter.handle_webauthn_register_start(
        _request(
            method="POST",
            path="/webauthn/register/start",
            form_data={
                "session_id": token_resp.body["session_id"],
                "user_name": "alice@example.com",
                "rp_id": "localhost",
                "rp_name": "Astra FastAPI Example",
            },
        )
    )
    assert isinstance(register_start.body, dict)
    register_finish = SERVICE.adapter.handle_webauthn_register_finish(
        _request(
            method="POST",
            path="/webauthn/register/finish",
            form_data={
                "state_id": register_start.body["state_id"],
                "credential_id": "cred-demo",
                "public_key": "public-key-demo",
                "transports": "internal,hybrid",
                "sign_count": "1",
            },
        )
    )
    assert isinstance(register_finish.body, dict)
    return register_finish.body


@APP.get("/")
def index() -> dict[str, object]:
    return {
        "app": APP.title,
        "base_url": APP_BASE_URL,
        "tenant_id": TENANT_ID,
        "client_id": CLIENT_ID,
        "demo_user": {"username": USERNAME, "password": PASSWORD, "api_key": API_KEY},
        "mounted_routes": [
            "/authorize",
            "/token",
            "/logout",
            "/introspect",
            "/mfa/challenge",
            "/mfa/verify",
            "/webauthn/register/start",
            "/webauthn/register/finish",
            "/webauthn/authenticate/start",
            "/webauthn/authenticate/finish",
            "/oidc/login/start",
            "/oidc/callback",
            "/.well-known/jwks.json",
            "/.well-known/openid-configuration",
            "/auth/ext/demo/runtime",
        ],
        "demo_helpers": [
            "/demo/password-token",
            "/demo/api-key-token",
            "/demo/password-email-otp",
            "/demo/password-webauthn",
            "/demo/oidc-federation",
            "/demo/email-otp/latest",
            "/demo/oidc-audit",
        ],
    }


@APP.get("/demo/password-token")
def demo_password_token() -> dict[str, object]:
    token_resp = SERVICE.adapter.handle_token(
        _request(
            method="POST",
            path="/token",
            form_data={
                "grant_type": "password",
                "client_id": CLIENT_ID,
                "tenant_id": TENANT_ID,
                "username": USERNAME,
                "password": PASSWORD,
                "scope": "openid",
            },
        )
    )
    assert isinstance(token_resp.body, dict)
    introspection = SERVICE.adapter.handle_introspect(
        _request(
            method="POST",
            path="/introspect",
            form_data={"token": token_resp.body["access_token"]},
        )
    )
    return {
        "token_response": token_resp.body,
        "introspection": introspection.body,
    }


@APP.get("/demo/api-key-token")
def demo_api_key_token() -> dict[str, object]:
    token_resp = SERVICE.adapter.handle_token(
        _request(
            method="POST",
            path="/token",
            form_data={
                "grant_type": "urn:astraauth:grant-type:api_key",
                "client_id": CLIENT_ID,
                "tenant_id": TENANT_ID,
                "api_key": API_KEY,
                "scope": "openid",
            },
        )
    )
    return {"token_response": token_resp.body}


@APP.get("/demo/password-email-otp")
def demo_password_email_otp() -> dict[str, object]:
    token_resp = SERVICE.adapter.handle_token(
        _request(
            method="POST",
            path="/token",
            form_data={
                "grant_type": "password",
                "client_id": CLIENT_ID,
                "tenant_id": TENANT_ID,
                "username": USERNAME,
                "password": PASSWORD,
                "scope": "openid",
                "required_acr": "2",
                "preferred_factor_type": "email_otp",
            },
        )
    )
    assert isinstance(token_resp.body, dict)
    otp_code = SERVICE.email_delivery.sent_messages[-1]["code"]
    verify_resp = SERVICE.adapter.handle_mfa_verify(
        _request(
            method="POST",
            path="/mfa/verify",
            form_data={
                "session_id": token_resp.body["session_id"],
                "challenge_id": token_resp.body["challenge_id"],
                "factor_type": "email_otp",
                "code": otp_code,
            },
        )
    )
    return {
        "step_up_start": token_resp.body,
        "latest_code": otp_code,
        "verification": verify_resp.body,
    }


@APP.get("/demo/password-webauthn")
def demo_password_webauthn() -> dict[str, object]:
    registration = _ensure_webauthn_credential()
    token_resp = SERVICE.adapter.handle_token(
        _request(
            method="POST",
            path="/token",
            form_data={
                "grant_type": "password",
                "client_id": CLIENT_ID,
                "tenant_id": TENANT_ID,
                "username": USERNAME,
                "password": PASSWORD,
                "scope": "openid",
                "required_acr": "2",
                "preferred_factor_type": "webauthn",
            },
        )
    )
    assert isinstance(token_resp.body, dict)
    finish_auth = SERVICE.adapter.handle_webauthn_authenticate_finish(
        _request(
            method="POST",
            path="/webauthn/authenticate/finish",
            form_data={
                "session_id": token_resp.body["session_id"],
                "state_id": token_resp.body["state_id"],
                "credential_id": "cred-demo",
                "sign_count": "2",
            },
        )
    )
    return {
        "registration": registration,
        "step_up_start": token_resp.body,
        "authentication_finish": finish_auth.body,
    }


@APP.get("/demo/oidc-federation")
def demo_oidc_federation() -> dict[str, object]:
    redirect_uri = f"{APP_BASE_URL}/oidc/callback"
    start = SERVICE.adapter.handle_oidc_login_start(
        _request(
            method="POST",
            path="/oidc/login/start",
            form_data={
                "provider_id": OIDC_PROVIDER_ID,
                "tenant_id": TENANT_ID,
                "redirect_uri": redirect_uri,
            },
        )
    )
    assert start.headers is not None
    state = parse_qs(urlparse(start.headers["Location"]).query)["state"][0]
    callback = SERVICE.adapter.handle_oidc_callback(
        _request(
            method="GET",
            path="/oidc/callback",
            query_params={
                "provider_id": OIDC_PROVIDER_ID,
                "tenant_id": TENANT_ID,
                "client_id": CLIENT_ID,
                "redirect_uri": redirect_uri,
                "code": "demo-auth-code",
                "state": state,
                "scope": "openid",
            },
        )
    )
    return {
        "login_start": {"status": start.status, "location": start.headers["Location"]},
        "callback": callback.body,
        "audit": [
            asdict(record) for record in SERVICE.list_oidc_audit_records(tenant_id=TENANT_ID)
        ],
    }


@APP.get("/demo/email-otp/latest")
def demo_latest_email_otp() -> dict[str, object]:
    latest = (
        SERVICE.email_delivery.sent_messages[-1] if SERVICE.email_delivery.sent_messages else None
    )
    return {"latest_message": latest}


@APP.get("/demo/oidc-audit")
def demo_oidc_audit() -> dict[str, object]:
    return {
        "records": [
            asdict(record) for record in SERVICE.list_oidc_audit_records(tenant_id=TENANT_ID)
        ]
    }


@APP.get("/demo/idp/.well-known/openid-configuration")
def demo_provider_configuration() -> dict[str, object]:
    base = f"{APP_BASE_URL}/demo/idp"
    return {
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "jwks_uri": f"{base}/jwks",
        "userinfo_endpoint": f"{base}/userinfo",
    }


@APP.get("/demo/idp/authorize")
def demo_provider_authorize(state: str, redirect_uri: str) -> dict[str, str]:
    return {"state": state, "redirect_uri": redirect_uri, "code": "demo-auth-code"}


@APP.post("/demo/idp/token")
def demo_provider_token() -> dict[str, str]:
    return {
        "access_token": "demo-external-access-token",
        "token_type": "Bearer",
        "id_token": "demo-id-token",
    }


@APP.get("/demo/idp/userinfo")
def demo_provider_userinfo() -> dict[str, object]:
    return {
        "sub": "external-user-1",
        "email": "alice@example.com",
        "email_verified": True,
        "groups": ["admins"],
        "department": "Platform",
    }


@APP.get("/demo/idp/jwks")
def demo_provider_jwks() -> dict[str, object]:
    return {"keys": []}


def build_app() -> FastAPI:
    return APP


def main() -> None:
    app = build_app()
    print("Created FastAPI app:", app.title)
    print("Mounted AstraAuth OAuth, MFA, WebAuthn, OIDC, and plugin demo routes.")
    print("Set ASTRAAUTH_EXAMPLE_SERVE=1 to run Uvicorn on 127.0.0.1:8000.")
    if getenv("ASTRAAUTH_EXAMPLE_SERVE") != "1":
        return
    try:
        import uvicorn
    except ImportError:
        print("Install FastAPI and Uvicorn first: uv sync --all-groups")
        return

    uvicorn.run(app, host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    main()
