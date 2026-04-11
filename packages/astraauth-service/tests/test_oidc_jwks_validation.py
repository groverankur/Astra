import json
from datetime import UTC, datetime, timedelta

from astraauth_idp import OIDCProviderConfig, OIDCProviderMetadata, OIDCTokenResponse
from astraauth_service.factory import HTTPOIDCCodeExchangeClient
from joserfc import jwk, jws


def test_http_oidc_exchange_client_validates_id_token_against_jwks() -> None:
    key = jwk.RSAKey.generate_key(2048)
    keyset = jwk.KeySet.import_key_set(jwk.KeySetSerialization(keys=[key.as_dict(is_private=False)]))
    client = HTTPOIDCCodeExchangeClient()
    client._jwks_cache["https://issuer.example.com/jwks"] = keyset

    now = datetime.now(tz=UTC)
    token = jws.serialize_compact(
        protected={"alg": "RS256"},
        payload=json.dumps(
            {
                "iss": "https://issuer.example.com",
                "sub": "ext-user-1",
                "aud": "ext-client",
                "nonce": "nonce-1",
                "iat": int(now.timestamp()),
                "exp": int((now + timedelta(minutes=5)).timestamp()),
            }
        ),
        private_key=key,
    )

    claims = client.validate_id_token(
        provider=OIDCProviderConfig(
            provider_id="oidc-corp",
            issuer="https://issuer.example.com",
            client_id="ext-client",
        ),
        metadata=OIDCProviderMetadata(
            issuer="https://issuer.example.com",
            authorization_endpoint="https://issuer.example.com/oauth2/authorize",
            token_endpoint="https://issuer.example.com/oauth2/token",
            jwks_uri="https://issuer.example.com/jwks",
        ),
        token_response=OIDCTokenResponse(
            access_token="access-1",
            token_type="Bearer",
            id_token=token,
        ),
        expected_nonce="nonce-1",
    )

    assert claims.subject == "ext-user-1"
    assert claims.audience == ("ext-client",)
