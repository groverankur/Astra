# Multi-Factor Authentication

Astra supports three MFA paths in the current baseline:

- TOTP
- email OTP
- WebAuthn

## Current MFA Behavior

- challenges are persisted through repository contracts
- successful MFA upgrades session `acr` and `amr`
- `STEP_UP` decisions can trigger MFA flows
- TOTP and email OTP are available through the runtime and adapters
- WebAuthn includes repository and ceremony contracts plus hardened replay/state consumption

## Important Scope Note

WebAuthn is implemented as a strong baseline, but deeper production ceremony validation can still be expanded later if your deployment needs more vendor-specific coverage.

## Where MFA Lives

- general MFA models and flows: `astraauth-core`
- WebAuthn-specific contracts and persistence: `astraauth-webauthn`
- runtime composition and adapter wiring: `astraauth-service` and `astraauth-adapters`
