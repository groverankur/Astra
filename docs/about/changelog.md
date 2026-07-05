# Changelog

This changelog maps the implementation phases to release-style version milestones.

## 1.0.0 - 2026-07-05

### First production-ready public release
- **Package Consolidation**: Consolidated all modular package namespaces (`astraauth-core`, `astraauth-service`, `astraauth-adapters`, `astraauth-idp`, `astraauth-webauthn`) into a single unified `astraauth` root package (with submodules `core`, `service`, `adapters`, `idp`, `webauthn`, and `plugins`) for simplified installation and consistent namespaces.
- **ReBAC Policy Engine**: Implemented **Astra Niyam (`astraauth-policy`)** providing Zanzibar-inspired schema compiling and graph traversal check engine.
- **Multi-Tenancy Isolation**: Implemented **Astra Mandal (`astraauth-tenancy`)** providing async/thread-safe dynamic tenant context-bindings and routing middleware.
- **Admin UI Console**: Updated **Astra Netra (`astraauth-admin-ui`)** to add interactive ReBAC policy authoring view, schema validator nodes, and checking console.
- **Framework Integration Adapters**: Rewrote framework examples (ASGI, Flask, Django, Litestar, Robyn) to run as full E2E mock client verification suites.
- completed release-readiness hardening across redaction, encrypted bootstrap export, plugin trust policy, WebAuthn verifier safety, config key custody, adapter origin policy, admin UI readability, and supported-framework examples.
- documented ASGI, FastAPI, Flask, Django, Litestar, and Robyn as supported adapters with package-oriented examples.
- added strict release verification evidence for Ruff, Ty, package tests, docs, Bandit, pip-audit, package builds, Twine metadata checks, and install smoke tests.
- promoted `astraauth-admin-ui` into the publishable package set with operator-focused docs and examples.
## 0.5.3 - 2026-05-13

### Security hardening and operator diagnostics
- Argon2 password hashing became the default, with legacy SHA-256 verification retained only as a migration path
- stronger WebAuthn verifier support was added behind the optional `webauthn` extra, and service composition now prefers it when installed
- runtime and admin credential throttling moved to shared persisted storage for multi-process deployments
- plugin runtime trust boundaries were tightened with timeout/error classification, persisted audit records, and safer endpoint execution
- CLI, admin API, and browser admin UI now expose runtime security diagnostics and dedicated plugin audit exports
- browser admin UI package was promoted into the active public package set with dashboard-style operator workflows

## 0.5.1 - 2026-04-08

### Platform identity and release polish
- public platform branding updated from AstraAuth to Astra while keeping technical `astraauth-*` package names intact
- `astra` CLI entrypoint added and documented as the preferred runtime executable
- package metadata updated for the future public repo and docs domains
- MKDocs content rewritten to match the actual package/runtime surface
- minimum supported Python version lowered to `3.12` with UUIDv7 compatibility helpers for `3.12`/`3.13`
- repository release essentials added: MIT license, contributing guide, security policy, and code of conduct

### Packaging and docs
- package README files updated to expose the Astra public module names
- reserved future platform modules documented as planned, not implemented
- future frontend SDKs documented as planned, not implemented
- release-check workflow aligned to smoke-test the public `astra` command

## 0.5.0 - 2026-04-04

### Phase 8: Production-readiness baseline
- browser admin UI hardened with authenticated sessions, CSRF protection, admin audit logging, and setup-token gating
- bootstrap handling hardened with hashed admin passwords, hashed short-lived setup tokens, and bootstrap lockdown support
- CI expanded for adapters, operator surfaces, relational backend confidence, OIDC confidence, and security scanning
- release-check and publish workflows added
- backup verification, diagnostics, observability, disaster recovery, and production-readiness docs added
- browser admin UI moved to Jinja + Basecoat + htmx partial updates

## 0.4.0 - 2026-04-03

### Phase 7: Framework/tooling completion
- generic ASGI, Flask, and Django adapter wiring completed
- CLI expanded for schema, persistence, config export/import, state export/import, key management, diagnostics, and operator workflows
- Textual TUI and lightweight browser admin UI package added
- deployment-focused examples and package-level READMEs completed
- repo-wide ty type-check cleanup completed

## 0.3.0 - 2026-04-02

### Phase 6: Enterprise federation baseline
- OIDC discovery, callback handling, identity linking, claim/group mapping, and local session issuance implemented
- JWKS-backed ID token verification and federation audit persistence added
- hybrid authorization context prepared for IdP-derived attributes and roles
- SAML and LDAP/AD explicitly deferred from the current production baseline

## 0.2.0 - 2026-04-01

### Phase 5: MFA and WebAuthn baseline
- MFA challenge contracts and session-upgrade flow implemented
- TOTP and email OTP factors added
- WebAuthn contracts, repositories, and step-up flow added
- MFA and WebAuthn endpoints wired through adapters and service composition

## 0.1.0 - 2026-03-31

### Phase 0-4 baseline
- OAuth/session/token foundation implemented
- tenant claim normalization and repository/store baseline completed
- RBAC foundation and early hybrid policy contracts added
- plugin runtime, tenant registry, endpoint extension support, and hook isolation implemented
