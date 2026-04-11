# Astra

Astra is a package-first authentication and authorization platform for Python applications.

Minimum supported Python version: `3.12`

Technical compatibility remains under the existing Python package namespace:
- root distribution: `astraauth`
- Python imports: `astraauth_*`
- protocol identifiers already shipped in code remain unchanged

Public platform naming:
- Astra Yantra -> `astraauth-core`
- Astra Sutra -> `astraauth-service`
- Astra Setu -> `astraauth-adapters`
- Astra Tantra -> `astraauth-plugins`
- Astra Pramaan -> `astraauth-idp`
- Astra Mudra -> `astraauth-webauthn`
- Astra Dwaar -> `astraauth-cli`
- Astra Netra -> `astraauth-admin-ui` (planned for next release)

Current baseline:
- OAuth and OpenID Connect token flows
- custom API key grant support
- sessions, refresh tokens, introspection, and logout
- MFA with TOTP, email OTP, and WebAuthn contracts
- hybrid authorization with RBAC, ABAC-style policy rules, and `STEP_UP`
- plugin runtime and tenant plugin registry
- OIDC enterprise federation with audit trail
- driver-first relational persistence for SQLite, Postgres, and MySQL
- runtime bootstrap, health, schema, and admin setup helpers
- persisted token key management and operator export/import workflows
- an interactive CLI with prompt mode and optional Textual TUI
- browser admin UI is being polished locally and is planned for the next release

## Start Here

1. [docs/index.md](docs/index.md)
2. [docs/getting-started/installation.md](docs/getting-started/installation.md)
3. [docs/getting-started/quick-start.md](docs/getting-started/quick-start.md)
4. [docs/getting-started/configuration.md](docs/getting-started/configuration.md)
5. [docs/about/package-summary.md](docs/about/package-summary.md)

## Package Map

| Public Name | Technical Package | Purpose |
| --- | --- | --- |
| Astra Yantra | `astraauth-core` | framework-agnostic auth, token, config, persistence, and authorization domain logic |
| Astra Sutra | `astraauth-service` | runtime composition, bootstrap, observability, and operator helpers |
| Astra Setu | `astraauth-adapters` | framework wiring for FastAPI, Flask, Django, ASGI, and more |
| Astra Tantra | `astraauth-plugins` | plugin runtime, registry, hook contracts, and endpoint extension support |
| Astra Pramaan | `astraauth-idp` | OIDC federation baseline, identity linking, and mapping contracts |
| Astra Mudra | `astraauth-webauthn` | WebAuthn repositories, ceremony contracts, and MFA upgrades |
| Astra Dwaar | `astraauth-cli` | CLI, wizard, TUI, key management, diagnostics, and operator flows |
| Astra Netra | `astraauth-admin-ui` | planned browser-based operator dashboard for the next release |

Reserved future modules that are planned but not created yet:
- Astra Niyam -> `astraauth-policy`
- Astra Mandal -> `astraauth-tenancy`
- Astra Drishti -> `astraauth-observability`

Future SDKs that are planned but not created yet:
- Astra JS SDK -> `@astraauth/sdk-js`
- Astra React SDK -> `@astraauth/sdk-react`

## Repository Layout

```text
Astra/
|-- docs/
|-- examples/
|-- packages/
|   |-- astraauth-core/
|   |-- astraauth-adapters/
|   |-- astraauth-plugins/
|   |-- astraauth-idp/
|   |-- astraauth-webauthn/
|   |-- astraauth-service/
|   |-- astraauth-cli/
|   `-- astraauth-admin-ui/ (local only, next release)
`-- archive/
```

Archived material is preserved under `archive/` and `examples/archive/`.

## Common Commands

```bash
uv sync --all-groups
uv run ruff check .
uv run pytest -q
uv run astra health --json
```

## Install Matrix

- core contributor setup: `uv sync --all-groups`
- Flask adapter work: `uv sync --extra flask`
- Django adapter work: `uv sync --extra django`
- generic ASGI adapter work: `uv sync --extra asgi`
- Postgres relational testing: `uv sync --extra postgres`
- MySQL relational testing: `uv sync --extra mysql`
- TOTP support: `uv sync --extra otp`
- full workspace feature set: `uv sync --all-groups`

## Example Walkthroughs

- [examples/01_bootstrap_runtime.py](examples/01_bootstrap_runtime.py)
- [examples/02_password_email_otp_step_up.py](examples/02_password_email_otp_step_up.py)
- [examples/03_oidc_federation.py](examples/03_oidc_federation.py)
- [examples/04_hybrid_authorization.py](examples/04_hybrid_authorization.py)
- [examples/05_asgi_app.py](examples/05_asgi_app.py)
- [examples/06_flask_app.py](examples/06_flask_app.py)
- [examples/07_config_reload.py](examples/07_config_reload.py)
- [examples/08_flask_deployment.py](examples/08_flask_deployment.py)
- [examples/09_django_deployment.py](examples/09_django_deployment.py)

## What Is Still Left

Repo implementation is complete through the current Phase 8 baseline.

What remains is mostly external or intentionally deferred:
- configure trusted publishing on PyPI/TestPyPI and run the first live release
- decide later whether `SAML` and `LDAP/AD` should become real packages
- decide later whether the planned JS/React SDKs should be created

## Repository Policies

- [LICENSE](LICENSE)
- [SECURITY.md](SECURITY.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

