# Package Summary

## Active Packages

### AstraAuth Root Package (`astraauth`)

The central, multi-module Python package enclosing the core platform capabilities:

| Submodule | Sanskrit Brand | Technical Namespace | Key Responsibilities |
| :--- | :--- | :--- | :--- |
| **Core Domain** | `Astra Yantra` | `astraauth.core` | Relational persistence models, settings validation, constant-time checks, rate limits, and cryptographic keys. |
| **Service Composition** | `Astra Sutra` | `astraauth.service` | Dependency factory injection, database pools, metrics aggregation, log redaction, and observers. |
| **Framework Adapters** | `Astra Setu` | `astraauth.adapters` | Route generators, middleware bindings, and HTTP request adapters (FastAPI, Django, Flask, Litestar, Robyn). |
| **Identity Providers** | `Astra Pramaan` | `astraauth.idp` | Federated OIDC settings, callback verifications, and external identity linking. |
| **WebAuthn Ceremonies** | `Astra Mudra` | `astraauth.webauthn` | FIDO2 challenge verification, credentials store, and signature assertions. |
| **Plugins Runtime** | — | `astraauth.plugins` | Event hooks runtime, sandboxed execution boundaries, and timeout limits. |

### Plugins Hub (`astraauth-plugins` / Astra Tantra)
Technical package: `astraauth-plugins`

Features:
- Main registry hub for built-in plugins (`GeoSignalPlugin`, `RiskSignalPlugin`) and third-party extensions.
- Re-exports core plugin lifecycle interfaces from `astraauth.plugins` for backwards compatibility.

### ReBAC Policy Engine (`astraauth-policy` / Astra Niyam)
Technical package: `astraauth-policy` (Namespace: `astraauth_policy`)

Features:
- Zanzibar-style relationship-based access control (ReBAC) system.
- Parser and compiler for KeyNetra-style schema DSL.
- Graph check query solver (`CheckEngine`) with transitive lookup and loop prevention.

### Multi-Tenancy Isolation (`astraauth-tenancy` / Astra Mandal)
Technical package: `astraauth-tenancy` (Namespace: `astraauth_tenancy`)

Features:
- Dynamic tenant workspace modeling and limits mapping.
- Async/thread-safe `ContextVar` workspace boundaries.
- ASGI middleware (`ASGITenancyMiddleware`) and Flask routing context bindings.

### Operator CLI (`astraauth-cli` / Astra Dwaar)
Technical package: `astraauth-cli`

Features:
- CLI utilities and interactive initialization wizards.
- Textual-based terminal TUI panel.
- Backup, export, and import tasks for encrypted configuration states.

### Browser Admin UI (`astraauth-admin-ui` / Astra Netra)
Technical package: `astraauth-admin-ui`

Features:
- Browser operator dashboard using FastAPI and HTMY templates.
- CSRF-protected admin tasks (key rotations, session checks, tenant creation).
- HTMX-driven dynamic views and observability logs.

---

## Reserved Future Modules

Planned roadmap modules (not implemented yet):

- **Astra Drishti (`astraauth-observability`)**: Telemetry metrics collector, trace exporter, and analytics dashboard.

---

## Future SDKs

Planned client SDKs (not implemented yet):

- **Astra JS SDK** (`@astraauth/sdk-js`)
- **Astra React SDK** (`@astraauth/sdk-react`)
