from urllib.parse import parse_qs, urlparse

from astraauth.core.adapters.http_types import HttpResponse, NormalizedRequestContext
from astraauth.core.authorization.models import Role
from astraauth.core.oauth.models import OAuthClient
from astraauth.idp import (
    ClaimAttributeMapping,
    GroupRoleMapping,
    OIDCIDTokenClaims,
    OIDCProviderConfig,
    OIDCTokenResponse,
    OIDCUserInfo,
)
from astraauth.service import build_inmemory_service


def _body(response: HttpResponse) -> dict[str, object]:
    body = response.body
    assert isinstance(body, dict)
    return body


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
        return OIDCTokenResponse(
            access_token="external-access", token_type="Bearer", id_token="external-id"
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


def test_service_adapter_handles_oidc_login_and_callback() -> None:
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
    svc.add_role(Role(name="local_admin", permissions={"openid"}))
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
    svc.assign_roles(
        subject_id="idp:tenant-1:oidc-corp:ext-user-1",
        tenant_id="tenant-1",
        roles={"local_admin"},
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

    start = svc.adapter.handle_oidc_login_start(
        NormalizedRequestContext(
            http_method="POST",
            request_path="/oidc/login/start",
            query_params={},
            headers={},
            form_data={
                "provider_id": "oidc-corp",
                "tenant_id": "tenant-1",
                "redirect_uri": "https://client.local/callback",
            },
        )
    )
    assert start.status == 302
    assert start.headers is not None
    location = start.headers["Location"]
    query = parse_qs(urlparse(location).query)
    state = query["state"][0]

    callback = svc.adapter.handle_oidc_callback(
        NormalizedRequestContext(
            http_method="GET",
            request_path="/oidc/callback",
            query_params={
                "provider_id": "oidc-corp",
                "tenant_id": "tenant-1",
                "client_id": "client-1",
                "redirect_uri": "https://client.local/callback",
                "code": "auth-code-1",
                "state": state,
                "scope": "openid",
            },
            headers={},
        )
    )

    assert callback.status == 200
    callback_body = _body(callback)
    assert callback_body["provider_id"] == "oidc-corp"
    assert callback_body["resolved_roles"] == ["employee"]
    assert callback_body["subject_attributes"] == {"department": "finance"}
    assert isinstance(callback_body["access_token"], str)
    assert isinstance(callback_body["refresh_token"], str)
    merged_assignment = svc.assignments.get_assignments(
        "idp:tenant-1:oidc-corp:ext-user-1", "tenant-1"
    )
    assert merged_assignment is not None
    assert merged_assignment.roles == {"employee", "local_admin"}
    audit = svc.list_oidc_audit_records(tenant_id="tenant-1", provider_id="oidc-corp")
    assert audit[-1].status == "succeeded"
