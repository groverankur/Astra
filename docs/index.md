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

| Public Name | Technical Package / Namespace |
| --- | --- |
| Astra Yantra | `astraauth (astraauth.core)` |
| Astra Sutra | `astraauth (astraauth.service)` |
| Astra Setu | `astraauth (astraauth.adapters)` |
| Astra Tantra | `astraauth-plugins` / `astraauth.plugins` |
| Astra Pramaan | `astraauth (astraauth.idp)` |
| Astra Mudra | `astraauth (astraauth.webauthn)` |
| Astra Niyam | `astraauth-policy` |
| Astra Mandal | `astraauth-tenancy` |
| Astra Dwaar | `astraauth-cli` |
| Astra Netra | `astraauth-admin-ui` |

Core platform submodules are importable via `astraauth.<submodule>` (e.g. `astraauth.core`).

## Current Status

- **Consolidated Layout**: Core domain, service execution, adapters, IDP federations, and WebAuthn verifications compile inside a single `astraauth` root package.
- **Access Policies & Multi-Tenancy**: Zanzibar-style relationship access control (ReBAC) is provided by `astraauth-policy`, and thread-safe dynamic tenant routing middleware is provided by `astraauth-tenancy`.
- **Plugins Hub**: `astraauth-plugins` is a dedicated plugin hub housing the standard builtin plugins and serving as the hook registration target for community extensions.
- **Tooling Packages**: CLI tool (`astraauth-cli`) and Admin web console (`astraauth-admin-ui`) run alongside the core library.
- **Deferred by Decision**: `SAML`, `LDAP/AD` sync bridges, JS SDK, and React SDK.

## Start Here

1. [Installation](getting-started/installation.md)
2. [Quick Start](getting-started/quick-start.md)
3. [Configuration](getting-started/configuration.md)
4. [Package Summary](about/package-summary.md)
5. [AstraAuth System Context, Architecture & Workflow Reference](about/architecture_and_workflows.md)
6. [Package-by-Package Context, Architecture & Workflows](about/package_detailed_references.md)
7. [Contributing](about/contributing.md)
8. [Security](about/security.md)

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
