from __future__ import annotations

import base64

from joserfc import jwk, jwt

from astraauth.core.oauth.errors import InvalidClientError
from astraauth.core.oauth.models import OAuthClient

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


def authenticate_client(
    *,
    client: OAuthClient,
    authorization_header: str | None,
    form_client_id: str | None,
    form_client_secret: str | None,
    client_assertion_type: str | None,
    client_assertion: str | None,
    token_endpoint: str,
) -> None:
    if client.client_type == "public":
        # Public clients MUST NOT authenticate
        return

    if client.auth_method == "client_secret_basic":
        _authenticate_basic(client, authorization_header)

    elif client.auth_method == "client_secret_post":
        _authenticate_post(client, form_client_id, form_client_secret)

    elif client.auth_method == "private_key_jwt":
        _authenticate_private_key_jwt(
            client=client,
            client_assertion_type=client_assertion_type,
            client_assertion=client_assertion,
            token_endpoint=token_endpoint,
        )
    else:
        raise InvalidClientError("Unsupported client authentication method")


def _authenticate_basic(
    client: OAuthClient,
    authorization_header: str | None,
) -> None:
    if not authorization_header or not authorization_header.startswith("Basic "):
        raise InvalidClientError("Missing Authorization header")

    encoded = authorization_header.removeprefix("Basic ").strip()

    try:
        decoded = base64.b64decode(encoded).decode("utf-8")
        client_id, secret = decoded.split(":", 1)
    except Exception:
        raise InvalidClientError("Invalid basic authentication encoding")  # noqa: B904

    if client_id != client.client_id:
        raise InvalidClientError("Client ID mismatch")

    if not client.client_secret or secret != client.client_secret:
        raise InvalidClientError("Invalid client secret")


def _authenticate_post(
    client: OAuthClient,
    form_client_id: str | None,
    form_client_secret: str | None,
) -> None:
    if form_client_id != client.client_id:
        raise InvalidClientError("Client ID mismatch")

    if not client.client_secret or form_client_secret != client.client_secret:
        raise InvalidClientError("Invalid client secret")


def _authenticate_private_key_jwt(
    *,
    client: OAuthClient,
    client_assertion_type: str | None,
    client_assertion: str | None,
    token_endpoint: str,
) -> None:
    if client_assertion_type != CLIENT_ASSERTION_TYPE:
        raise InvalidClientError("Invalid client_assertion_type")

    if not client_assertion:
        raise InvalidClientError("Missing client_assertion")

    if not client.jwks:
        raise InvalidClientError("Client JWKS not configured")

    key_data = jwk.KeySetSerialization(keys=client.jwks.get("keys", []))

    keyset = jwk.KeySet.import_key_set(key_data)

    try:
        token = jwt.decode(
            client_assertion,
            keyset,
        )

        claims = token.claims

    except Exception as e:
        raise InvalidClientError("Invalid client assertion") from e

    # REQUIRED CLAIMS

    if claims.get("iss") != client.client_id:
        raise InvalidClientError("Invalid issuer")

    if claims.get("sub") != client.client_id:
        raise InvalidClientError("Invalid subject")

    if claims.get("aud") != token_endpoint:
        raise InvalidClientError("Invalid audience")
