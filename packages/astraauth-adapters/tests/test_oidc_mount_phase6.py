from urllib.parse import parse_qs, urlparse

from astraauth_adapters.fastapi.wiring import mount_oauth
from astraauth_core.authorization.models import Role
from astraauth_core.oauth.models import OAuthClient
from astraauth_idp import (
    ClaimAttributeMapping,
    GroupRoleMapping,
    OIDCIDTokenClaims,
    OIDCProviderConfig,
    OIDCTokenResponse,
    OIDCUserInfo,
)
from astraauth_service import build_inmemory_service
from fastapi import FastAPI
from fastapi.testclient import TestClient


class _MetadataClient:
    def fetch_metadata(self, *, discovery_url: str) -> dict[str, object]:
        _ = discovery_url
        return {
            "issuer": "https://issuer.example.com",
            "authorization_endpoint": "https://issuer.example.com/oauth2/authorize",
            "token_endpoint": "https://issuer.example.com/oauth2/token",
            "jwks_uri": "https://issuer.example.com/.well-known/jwks.json",
            "userinfo_endpoint": "https://issuer.example.com/oauth2/userinfo",
        }


class _ExchangeClient:
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
        assert code == "auth-code-1"
        return OIDCTokenResponse(access_token="external-access", token_type="Bearer", id_token="external-id")

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
            issuer="https://issuer.example.com",
            subject="ext-user-1",
            audience=("ext-client",),
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
            subject="ext-user-1",
            email="alice@example.com",
            email_verified=True,
            claims={"groups": ("admins",), "department": "Finance"},
        )


def test_mount_oauth_exposes_oidc_login_and_callback_routes() -> None:
    app = FastAPI()
    svc = build_inmemory_service(default_plugins_enabled=False)
    svc.register_oidc_provider(
        provider=OIDCProviderConfig(
            provider_id="oidc-corp",
            issuer="https://issuer.example.com",
            client_id="ext-client",
            client_secret="ext-secret",
        )
    )
    svc.oidc_handler._metadata_client = _MetadataClient()
    svc.oidc_handler._exchange_client = _ExchangeClient()
    svc.add_role(Role(name="employee", permissions={"openid"}))
    svc.add_client(
        OAuthClient(
            client_id="client-1",
            redirect_uris={"https://client.local/callback"},
            allowed_scopes={"openid"},
            allowed_tenants={"tenant-1"},
            client_type="public",
            auth_method="none",
            require_pkce=False,
        )
    )
    svc.add_oidc_group_role_mapping(
        GroupRoleMapping(
            provider_id="oidc-corp",
            tenant_id="tenant-1",
            external_group="admins",
            role_name="employee",
        )
    )
    svc.add_oidc_claim_attribute_mapping(
        ClaimAttributeMapping(
            provider_id="oidc-corp",
            tenant_id="tenant-1",
            claim_name="department",
            attribute_name="department",
            transform="lower",
        )
    )

    mount_oauth(app, svc.adapter)
    client = TestClient(app)

    start = client.post(
        "/oidc/login/start",
        data={
            "provider_id": "oidc-corp",
            "tenant_id": "tenant-1",
            "redirect_uri": "https://client.local/callback",
        },
        follow_redirects=False,
    )
    assert start.status_code == 302
    assert start.headers["x-correlation-id"]
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]

    callback = client.get(
        "/oidc/callback",
        params={
            "provider_id": "oidc-corp",
            "tenant_id": "tenant-1",
            "client_id": "client-1",
            "redirect_uri": "https://client.local/callback",
            "code": "auth-code-1",
            "state": state,
            "scope": "openid",
        },
    )
    assert callback.status_code == 200
    assert callback.headers["x-correlation-id"]
    payload = callback.json()
    assert payload["provider_id"] == "oidc-corp"
    assert payload["resolved_roles"] == ["employee"]
    assert payload["subject_attributes"] == {"department": "finance"}
