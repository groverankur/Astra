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
- Astra Netra -> `astraauth-admin-ui`

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
- browser admin UI with authenticated setup, audit views, and htmx-driven partial dashboard updates

## Start Here

* **Medium Article**: [Introducing Astra: The Unified Authentication and Authorization Platform for Python](https://medium.com/@groverankur/from-experiment-to-platform-how-astra-became-pythons-unified-authentication-layer-cfb32655efbc?sharedUserId=groverankur)
1. [docs/index.md](docs/index.md)
2. [docs/getting-started/installation.md](docs/getting-started/installation.md)
3. [docs/getting-started/quick-start.md](docs/getting-started/quick-start.md)
4. [docs/getting-started/configuration.md](docs/getting-started/configuration.md)
5. [docs/about/package-summary.md](docs/about/package-summary.md)

## Package Map

| Public Name   | Technical Package    | Purpose                                                                             |
| ------------- | -------------------- | ----------------------------------------------------------------------------------- |
| Astra Yantra  | `astraauth-core`     | framework-agnostic auth, token, config, persistence, and authorization domain logic |
| Astra Sutra   | `astraauth-service`  | runtime composition, bootstrap, observability, and operator helpers                 |
| Astra Setu    | `astraauth-adapters` | framework wiring for FastAPI, Flask, Django, ASGI, and more                         |
| Astra Tantra  | `astraauth-plugins`  | plugin runtime, registry, hook contracts, and endpoint extension support            |
| Astra Pramaan | `astraauth-idp`      | OIDC federation baseline, identity linking, and mapping contracts                   |
| Astra Mudra   | `astraauth-webauthn` | WebAuthn repositories, ceremony contracts, and MFA upgrades                         |
| Astra Dwaar   | `astraauth-cli`      | CLI, wizard, TUI, key management, diagnostics, and operator flows                   |
| Astra Netra   | `astraauth-admin-ui` | browser-based operator dashboard for setup, health, keys, and audit workflows       |

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
|   `-- astraauth-admin-ui/
```

## Common Commands

```bash
uv sync --all-groups
uv run ruff check .
uv run pytest -q
uv run zensical build --strict
uv run astra health --json
```

## Install Matrix

- core contributor setup: `uv sync --all-groups`
- Flask adapter work: `uv pip install -e "packages/astraauth-adapters[flask]"`
- Django adapter work: `uv pip install -e "packages/astraauth-adapters[django]"`
- generic ASGI adapter work: `uv pip install -e "packages/astraauth-adapters[asgi]"`
- all supported adapter extras: `uv pip install -e "packages/astraauth-adapters[all]"`
- Postgres relational testing: `uv pip install -e "packages/astraauth-core[postgres]"`
- MySQL relational testing: `uv pip install -e "packages/astraauth-core[mysql]"`
- TOTP support: `uv pip install -e "packages/astraauth-core[otp]"`
- full workspace feature set: `uv sync --all-groups`

## Example Walkthroughs

- [examples/fastapi_app.py](examples/fastapi_app.py) — Polished FastAPI end-to-end example with dark-mode UI
- [examples/flask_app.py](examples/flask_app.py) — Polished Flask end-to-end example with dark-mode UI
- [examples/django_app.py](examples/django_app.py) — Polished Django end-to-end example served via ASGI (Uvicorn)
- [examples/litestar_app.py](examples/litestar_app.py) — Polished Litestar end-to-end example with dark-mode UI
- [examples/robyn_app.py](examples/robyn_app.py) — Polished Robyn end-to-end example with Rust-backed async runtime
- [examples/20_fastapi_dashboard.py](examples/20_fastapi_dashboard.py) — Full interactive CRUD & security dashboard app
- [examples/21_better_auth_demo.py](examples/21_better_auth_demo.py) — Better-Auth style interactive security dashboard (MFA, session auditing)
- [examples/archive/](examples/archive/) — Original development and adapter verification examples (01–19)

## What Is Still Left

Repo implementation is in strong shape through the current Phase 8 baseline, but a few hardening and release tasks still remain.

What remains is mostly external, hardening-oriented, or intentionally deferred:

- configure trusted publishing on PyPI/TestPyPI and run the first live release
- continue migrating older SHA-256 password records forward to the Argon2-based default
- continue expanding WebAuthn deployment guidance and deeper ceremony coverage where needed
- decide later whether `SAML` and `LDAP/AD` should become real packages
- decide later whether the planned JS/React SDKs should be created

## Repository Policies

- [LICENSE](LICENSE)
- [SECURITY.md](SECURITY.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

## Documentation Stack

- static site generator: `Zensical`
- theme variant: `classic` for Material-style familiarity
- config: [zensical.toml](zensical.toml)
