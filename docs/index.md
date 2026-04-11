# Astra Docs

Astra is the public platform name for the current `astraauth-*` package family.

## What Astra provides

- OAuth token issuance, refresh, introspection, logout, and normalized tenant claims
- password, authorization-code, refresh-token, and custom API key grant support
- hybrid authorization with `ALLOW`, `DENY`, and `STEP_UP`
- MFA with TOTP, email OTP, and WebAuthn baseline support
- tenant-aware plugin runtime and plugin registry
- OIDC federation baseline with discovery, callback verification, JWKS validation, and audit persistence
- driver-first relational persistence for SQLite, PostgreSQL, and MySQL
- operator tooling through CLI and optional Textual TUI

## Branding Map

| Public Name | Technical Package |
| --- | --- |
| Astra Yantra | `astraauth-core` |
| Astra Sutra | `astraauth-service` |
| Astra Setu | `astraauth-adapters` |
| Astra Tantra | `astraauth-plugins` |
| Astra Pramaan | `astraauth-idp` |
| Astra Mudra | `astraauth-webauthn` |
| Astra Dwaar | `astraauth-cli` |
| Astra Netra | `astraauth-admin-ui` (planned for next release) |

Python imports and technical package names remain unchanged for compatibility.

## Current Status

- Phase 0-7: complete for the planned feature baseline
- Phase 8: complete for the current production-readiness repo baseline
- Browser admin UI remains local and is planned for the next release
- Deferred by decision: `SAML`, `LDAP/AD`, `astraauth-policy`, `astraauth-tenancy`, `astraauth-observability`, JS SDK, React SDK

## Start Here

1. [Installation](getting-started/installation.md)
2. [Quick Start](getting-started/quick-start.md)
3. [Configuration](getting-started/configuration.md)
4. [Package Summary](about/package-summary.md)
5. [Status and Scope](about/status.md)
6. [Contributing](about/contributing.md)
7. [Security](about/security.md)

## Quick Commands

```bash
uv sync --all-groups
uv run astra version
uv run astra config-init --home .astraauth --environment dev --persistence-backend sqlite
uv run astra schema-ensure --home .astraauth --json
uv run astra health --home .astraauth --json
```

## Important Compatibility Note

Astra implements a custom API key grant:

```text
urn:astraauth:grant-type:api_key
```

That is implemented in code today. A Financial-grade API (FAPI) profile is not implemented or claimed.
