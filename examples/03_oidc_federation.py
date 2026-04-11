from __future__ import annotations

from pprint import pprint
from urllib.parse import parse_qs, urlparse

from astraauth_core.adapters.http_types import NormalizedRequestContext
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


class DemoMetadataClient:
    def fetch_metadata(self, *, discovery_url: str) -> dict[str, object]:
        _ = discovery_url
        return {
            'issuer': 'https://issuer.example.com',
            'authorization_endpoint': 'https://issuer.example.com/oauth2/authorize',
            'token_endpoint': 'https://issuer.example.com/oauth2/token',
            'jwks_uri': 'https://issuer.example.com/.well-known/jwks.json',
            'userinfo_endpoint': 'https://issuer.example.com/oauth2/userinfo',
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
        assert code == 'demo-auth-code'
        return OIDCTokenResponse(access_token='external-access-token', token_type='Bearer', id_token='demo-id-token')

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
            issuer='https://issuer.example.com',
            subject='ext-user-1',
            audience=('ext-client',),
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
            subject='ext-user-1',
            email='alice@example.com',
            email_verified=True,
            claims={'groups': ('admins',), 'department': 'Finance'},
        )


def main() -> None:
    service = build_inmemory_service(default_plugins_enabled=False)
    service.register_oidc_provider(
        provider=OIDCProviderConfig(
            provider_id='oidc-corp',
            issuer='https://issuer.example.com',
            client_id='ext-client',
            client_secret='ext-secret',
        )
    )
    service.oidc_handler._metadata_client = DemoMetadataClient()
    service.oidc_handler._exchange_client = DemoExchangeClient()

    service.add_role(Role(name='employee', permissions={'openid'}))
    service.add_client(
        OAuthClient(
            client_id='client-1',
            redirect_uris={'https://client.local/callback'},
            allowed_scopes={'openid'},
            allowed_tenants={'tenant-1'},
            client_type='public',
            auth_method='none',
            require_pkce=False,
        )
    )
    service.add_oidc_group_role_mapping(
        GroupRoleMapping(
            provider_id='oidc-corp',
            tenant_id='tenant-1',
            external_group='admins',
            role_name='employee',
        )
    )
    service.add_oidc_claim_attribute_mapping(
        ClaimAttributeMapping(
            provider_id='oidc-corp',
            tenant_id='tenant-1',
            claim_name='department',
            attribute_name='department',
            transform='lower',
        )
    )

    start = service.adapter.handle_oidc_login_start(
        NormalizedRequestContext(
            http_method='POST',
            request_path='/oidc/login/start',
            query_params={},
            headers={},
            form_data={
                'provider_id': 'oidc-corp',
                'tenant_id': 'tenant-1',
                'redirect_uri': 'https://client.local/callback',
            },
        )
    )
    assert start.headers is not None
    state = parse_qs(urlparse(start.headers['Location']).query)['state'][0]

    callback = service.adapter.handle_oidc_callback(
        NormalizedRequestContext(
            http_method='GET',
            request_path='/oidc/callback',
            query_params={
                'provider_id': 'oidc-corp',
                'tenant_id': 'tenant-1',
                'client_id': 'client-1',
                'redirect_uri': 'https://client.local/callback',
                'code': 'demo-auth-code',
                'state': state,
                'scope': 'openid',
            },
            headers={},
        )
    )

    print('callback result:')
    pprint(callback.body)
    print('\nfederation audit:')
    pprint(service.list_oidc_audit_records(tenant_id='tenant-1', provider_id='oidc-corp'))


if __name__ == '__main__':
    main()
