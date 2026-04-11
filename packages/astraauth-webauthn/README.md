# Astra Mudra (`astraauth-webauthn`)

WebAuthn and MFA-specific contracts for Astra.

## Best For

- projects that want WebAuthn registration/authentication flows without adopting the whole runtime
- custom ceremony composition on top of Astra session and MFA contracts
- sync or async SQL-backed WebAuthn repository usage

## Includes

- WebAuthn registration and authentication state models
- Sync and async SQL repositories
- Verifier abstraction for ceremony validation
- Session-upgrade compatible authentication flow

## Install

```bash
uv add astraauth-webauthn
```

Optional verification helper extra:

```bash
uv add "astraauth-webauthn[webauthn]"
```

The `webauthn` extra installs the Duo Labs server-side WebAuthn library
published on PyPI as `webauthn`, which is the stronger fit for future deeper
ceremony verification.

## Typical Use

```python
from astraauth_webauthn import (
    InMemoryWebAuthnCredentialRepository,
    InMemoryWebAuthnRegistrationStateRepository,
    begin_registration,
)

credentials = InMemoryWebAuthnCredentialRepository()
registration_states = InMemoryWebAuthnRegistrationStateRepository()
```

Use this package through `astraauth-service` when you want the default Astra
runtime behavior. Use it directly when you are composing your own WebAuthn
layer.

## Public API Areas

- registration/authentication state models
- credential repositories
- registration/authentication start and finish helpers
- verifier and challenge-generator contracts
- sync and async SQL repositories

## Tests

```bash
uv run pytest -q packages/astraauth-webauthn/tests
```
