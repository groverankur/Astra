# Authentication

Astra currently implements these authentication paths:

- authorization code
- password grant
- refresh token rotation
- custom API key grant
- MFA step-up using TOTP, email OTP, and WebAuthn
- OIDC federation through external identity providers

## Supported OAuth Grant Types

- `authorization_code`
- `password`
- `refresh_token`
- `urn:astraauth:grant-type:api_key`

## API Key Status

API key authentication is implemented in code as a custom OAuth grant path and runtime API key authenticator.

Important distinction:

- implemented: custom API key grant support
- not implemented: Financial-grade API (FAPI) compliance or certification

## Client Authentication

The current token endpoint supports:

- `client_secret_basic`
- `client_secret_post`

## Runtime Surface

The normalized HTTP adapter lives in `astraauth_core.adapters.oauth_http.OAuthHTTPAdapter`, and `astraauth-service` composes it with session stores, token management, MFA, plugins, and OIDC federation.

## Common Next Steps

- use [MFA](mfa.md) when a flow needs stronger assurance
- use [OIDC Federation](oidc-federation.md) when external providers are required
- use [Authorization](authorization.md) to enforce `ALLOW`, `DENY`, and `STEP_UP`
