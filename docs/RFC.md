# RFC Status

This RFC summary tracks what is implemented in the active Astra platform repo, what is complete, and what remains before the current `Astra-*` package family can be treated as a real production-ready package set.

## Baseline decisions

- `Astra-core` is the framework-agnostic domain layer.
- `Astra-service` is the runtime composition and bootstrap layer.
- `Astra-adapters` mounts the normalized HTTP adapter into framework runtimes.
- `Astra-cli` is the operator CLI surface.
- `Astra-admin-ui` is part of the active operator surface for browser-based runtime operations.
- relational persistence follows a driver-first repository approach with sync/async support.
- authorization uses a hybrid `RBAC + policy/attribute` model.
- OIDC is the enterprise federation baseline.
- SAML and LDAP/AD are explicitly deferred from the current production-ready baseline until a concrete deployment requires them.

## Phase status

### Phase 0-3
Completed.

Delivered:
- OAuth token flows, sessions, introspection, logout
- tenant claim normalization to `tid`
- repository unification and persistence contracts
- authorization decisions with `ALLOW`, `DENY`, `STEP_UP`
- event bus abstraction and plugin foundation

### Phase 4
Completed.

Delivered:
- tenant plugin registry
- in-memory and relational registry persistence
- hook timeout/isolation policy
- endpoint materialization helpers

### Phase 5
Completed.

Delivered:
- MFA challenges and session upgrade
- TOTP and email OTP flows
- WebAuthn repository and ceremony contracts
- adapter endpoints and route mounting
- step-up integration across token/session flow

### Phase 6
Completed as the current enterprise federation baseline.

Delivered:
- OIDC provider config and federation contracts
- discovery, login state, callback, identity linking
- claim-to-role and claim-to-attribute mapping
- JWKS-backed ID token verification
- federation audit persistence
- local session issuance after successful federation

Deferred:
- SAML federation
- LDAP/AD sync or auth bridge

### Phase 7
Completed for the current baseline.

Delivered:
- package-level docs refresh
- generic ASGI adapter wiring
- Flask adapter wiring
- Django adapter wiring
- CLI commands for health, persistence, schema, JWKS, key rotation, bootstrap admin setup, and state export/import
- deployment-focused Flask and Django examples
- repo-wide ty type-check cleanup
- prompt-driven interactive operator flows
- Textual terminal wizard/admin console
- browser-based FastAPI admin UI package

Follow-up track:
- broader framework coverage only if another framework is explicitly needed
- production hardening follow-up where optional integrations need it

## Phase 8
Completed for the repo baseline on April 4, 2026.

Goal:
- finish the work required for Astra to behave like a production-ready multi-package Python platform, not just a feature-complete implementation baseline.

### Phase 8 priorities

#### Must-have
- browser admin UI protection
  - require real admin authentication for web admin access
  - add CSRF/session protection for state-changing actions
  - add admin action audit logging for config, bootstrap, and key operations
- CI and release hardening
  - install and run framework adapter extras in CI instead of skipping them
  - run real security scanning in CI with enforced review/fail policy
  - add release/publish workflow for workspace packages
- packaging readiness
  - verify each active package installs standalone in a clean environment
  - verify package metadata and extras are publishable and internally consistent
  - add changelog/release-note process
- persistence and integration confidence
  - add real Postgres/MySQL integration validation paths where those backends are claimed
  - add real OIDC provider integration coverage beyond local fixture-style validation

#### Should-have
- WebAuthn hardening
  - stronger production-grade verifier/provider path
  - broader negative-path and replay/ceremony failure coverage
- operator/runtime safety
  - stronger backup/restore verification flows
  - richer diagnostics for config resolution, persistence, and key state
  - key custody guidance and optional secret-manager integration path
- observability
  - structured logging defaults
  - correlation IDs
  - auth, federation, and key-management metrics/events
- admin UI polish
  - validation and clearer UX for operator actions
  - local asset pipeline instead of CDN Tailwind for stricter deployment postures

#### Optional
- SAML federation decision and implementation track
- LDAP/AD bridge decision and implementation track
- broader adapter expansion beyond current supported frameworks
- richer policy management UI for hybrid authorization

## Phase 8 exit criteria

Phase 8 is considered complete for the current repo baseline because:
- admin-facing surfaces are protected and audited
- CI exercises claimed framework and security paths instead of skipping them
- package publishing/release workflow is documented and automated
- production docs reflect an end-to-end deployable operator path
- claimed persistence and federation backends have corresponding integration confidence

Deferred-by-decision:
- SAML is not required for the current baseline
- LDAP/AD is not required for the current baseline

## Current project conclusion

Astra is feature-complete through Phase 7 for the current roadmap baseline.

What remains is not foundational feature work. It is the productionization layer:
- hardening
- release engineering
- operator safety
- deployment confidence

