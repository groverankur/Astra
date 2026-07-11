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
- WebAuthn finish helpers always invoke a verifier and require full production ceremony inputs
- repeated MFA verification failures are throttled in the runtime adapter

## WebAuthn Production Requirements

- install the optional webauthn extra (e.g. `pip install "astraauth[webauthn]"`) for production ceremony verification
- provide the credential or authentication response, expected origin, and relying-party ID to finish helpers
- without the optional verifier library, production finish flows fail closed
- use `LocalDevelopmentWebAuthnVerifier(environment="dev")` only for explicit local demonstrations and tests
- sign counters must advance; a stored and returned value of zero is accepted for authenticators that do not implement counters

Deeper deployment-specific coverage may still be needed for environments with stricter interoperability requirements.

## Where MFA Lives

The multi-factor authentication (MFA) capabilities are divided cleanly across the active modules and namespaces:

| Scope / Component | Python Namespace | Sanskrit Brand | Responsibility |
| :--- | :--- | :--- | :--- |
| **Core Models & Flows** | `astraauth.core` | `Astra Yantra` | TOTP definitions, email OTP verification models, and runtime throttling rules. |
| **WebAuthn Ceremonies** | `astraauth.webauthn` | `Astra Mudra` | FIDO2 registration schemas, credential assertion verifiers, and SQL signature check stores. |
| **Wiring & Composition** | `astraauth.service` & `astraauth.adapters` | `Astra Sutra` & `Astra Setu` | Bootstrapping connection hooks, mapping session cookie properties, and framework adapters. |

## Abuse Controls

- repeated OTP verification failures are throttled by shared runtime state when the service uses shared persistence
- repeated WebAuthn authentication-finish failures are throttled through the same runtime mechanism
- single-process test or scratch runtimes still work with in-memory throttling when no shared persistence exists
