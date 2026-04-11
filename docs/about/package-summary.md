# Package Summary

## Active Packages

### Astra Yantra
Technical package: `astraauth-core`

Features:
- token and JOSE infrastructure
- OAuth grant handling
- sessions and refresh-token flow
- hybrid authorization contracts
- MFA models and repositories
- driver-first persistence config and contracts

### Astra Sutra
Technical package: `astraauth-service`

Features:
- runtime composition
- bootstrap helpers
- key management
- diagnostics, backups, observability, and audits

### Astra Setu
Technical package: `astraauth-adapters`

Features:
- FastAPI, Flask, Django, Litestar, Robyn, and generic ASGI wiring
- route mounting for OAuth, MFA, OIDC, and plugin endpoints

### Astra Tantra
Technical package: `astraauth-plugins`

Features:
- plugin contracts
- tenant enablement registry
- runtime hook execution
- endpoint extensions

### Astra Pramaan
Technical package: `astraauth-idp`

Features:
- OIDC provider config
- identity linking
- group/claim mapping
- federation callback verification and audit

### Astra Mudra
Technical package: `astraauth-webauthn`

Features:
- WebAuthn ceremony contracts
- credential and state repositories
- hardened state consumption and replay handling

### Astra Dwaar
Technical package: `astraauth-cli`

Features:
- operator CLI
- interactive wizard
- optional Textual TUI
- backup/export/import flows
- diagnostics and observability views

### Astra Netra
Technical package: `astraauth-admin-ui` (planned for next release)

Features:
- browser admin dashboard
- setup/login flow
- CSRF-protected admin actions
- audit views
- htmx-driven partial UI updates

Current status:
- retained locally for further polish
- not part of the current public commit boundary

## Reserved Future Modules

These are roadmap placeholders only. They are not created packages yet.

- Astra Niyam -> `astraauth-policy`
- Astra Mandal -> `astraauth-tenancy`
- Astra Drishti -> `astraauth-observability`

## Future SDKs

Also planned only, not implemented:

- Astra JS SDK -> `@astraauth/sdk-js`
- Astra React SDK -> `@astraauth/sdk-react`
