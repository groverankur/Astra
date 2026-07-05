# Package Summary

## Active Packages

### AstraAuth Root Package (`astraauth`)
The central Python package enclosing the core platform modules:
*   **Astra Yantra (`astraauth.core`)**: Domain logic for configurations, OAuth protocols, OIDC token signatures, sessions, MFA, persistence relational connectors, and cryptographic parameters.
*   **Astra Sutra (`astraauth.service`)**: Service composition, logging configurations, observers, metrics, and health diagnostics.
*   **Astra Setu (`astraauth.adapters`)**: thin integrations mapping standard HTTP requests to FastAPI, Django, Flask, Litestar, Robyn, and raw ASGI runtimes.
*   **Astra Pramaan (`astraauth.idp`)**: Federated identity mappings, Discovery protocols, OIDC callbacks, and identity linking.
*   **Astra Mudra (`astraauth.webauthn`)**: WebAuthn credential stores and assertion verifiers powered by the `fido2` library.
*   **Astra Tantra Engine (`astraauth.plugins`)**: Sandboxed plugin runtime registry, hook execution boundaries, and timeout monitors.

### Astra Tantra Hub (`astraauth-plugins`)
Technical package: `astraauth-plugins`

Features:
- Main registry hub for built-in signal plugins (`GeoSignalPlugin`, `RiskSignalPlugin`) and community-built extensions.
- Re-exports all core contracts and runtime managers from `astraauth.plugins` for backwards compatibility.

### Astra Dwaar (`astraauth-cli`)
Technical package: `astraauth-cli`

Features:
- Operator CLI utility and setup wizard.
- Optional Textual terminal TUI.
- Encrypted configuration backup, export, and import tasks.

### Astra Netra (`astraauth-admin-ui`)
Technical package: `astraauth-admin-ui`

Features:
- Browser-based operator dashboard utilizing FastAPI and Jinja2 templates.
- CSRF-protected admin operations (key rotations, session checks).
- HTMX-driven partial views and real-time audit logs.

### Astra Niyam (`astraauth-policy`)
Technical package: `astraauth-policy`

Features:
- Zanzibar-style relationship-based access control (ReBAC) policy model.
- Schema parser and compiler for KeyNetra-style schema DSL.
- Graph traversal solver (CheckEngine) with circular dependency protection and depth limit boundaries.

### Astra Mandal (`astraauth-tenancy`)
Technical package: `astraauth-tenancy`

Features:
- Dynamic tenant workspace modeling and limits mapping.
- ContextVar-based request context binding (async/thread safe).
- Built-in ASGI middleware and Flask before/after handlers for header-driven routing.

## Reserved Future Modules

These are roadmap placeholders only. They are not created packages yet.

- Astra Drishti -> `astraauth-observability`

## Future SDKs

Also planned only, not implemented:

- Astra JS SDK -> `@astraauth/sdk-js`
- Astra React SDK -> `@astraauth/sdk-react`
