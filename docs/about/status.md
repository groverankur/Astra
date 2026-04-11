# Status and Scope

## Implemented Today

- Phase 0-3: auth, sessions, token flows, core authorization baseline
- Phase 4: plugin runtime and registry
- Phase 5: MFA and WebAuthn baseline
- Phase 6: OIDC federation baseline
- Phase 7: framework adapters, CLI, TUI, docs, and examples
- Phase 8: production-readiness repo baseline

## What Is Left

Code and docs are complete for the current baseline.

What remains is external or optional:

- configure trusted publishing in PyPI/TestPyPI
- run the first real release
- follow the repository release policies in `LICENSE`, `SECURITY.md`, and `CONTRIBUTING.md`
- finish browser admin UI polish and publish it in the next release
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
