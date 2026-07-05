# Status and Scope

## Implemented Today

- Phase 0-3: auth, sessions, token flows, core authorization baseline
- Phase 4: plugin runtime and registry
- Phase 5: MFA and WebAuthn baseline
- Phase 6: OIDC federation baseline
- Phase 7: framework adapters, CLI, TUI, docs, and examples
- Phase 8: production-readiness repo baseline

## What Is Left

The repo baseline is in strong shape, but a few hardening and release tasks still remain:

- configure trusted publishing in PyPI/TestPyPI
- run the first real release
- follow the repository release policies in `LICENSE`, `SECURITY.md`, and `CONTRIBUTING.md`
- finish migrating older SHA-256 password records forward to the new Argon2-based default
- continue expanding WebAuthn ceremony coverage and deployment guidance beyond the current optional `webauthn` verifier path
- document and tune shared throttle storage behavior for larger clustered deployments as needed
- create deferred modules only if a concrete deployment requires them

## Explicitly Deferred

- `SAML`
- `LDAP/AD`
- `astraauth-policy`
- `astraauth-tenancy`
- `astraauth-observability`
- JS and React SDK packages

## Security/Protocol Clarification

Astra implements API key authentication through a custom grant, but it does not claim FAPI compliance.
WebAuthn is available today as a hardened baseline with replay/state-consumption protections, and stronger ceremony verification is available through the optional `webauthn` extra.
Runtime credential throttling and admin UI operator throttling are implemented today, and both now use shared storage rather than per-process memory in their default persisted deployment paths.
