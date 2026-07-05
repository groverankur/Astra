# Security Policy

## Supported Baseline

The active supported baseline is the current `1.x` line.

Production-oriented behavior is documented in:

- [`docs/about/package-summary.md`](docs/about/package-summary.md)
- [`docs/user-guide/abuse-controls.md`](docs/user-guide/abuse-controls.md)
- [`docs/about/security.md`](docs/about/security.md)

## Reporting a Vulnerability

Please report security issues privately first.

- Preferred contact: `grover.ankur@gmail.com`
- Subject suggestion: `Astra security report`

Please include:

- affected package(s)
- affected version(s)
- reproduction details
- impact assessment
- any proposed mitigation if available

Please avoid opening a public GitHub issue for undisclosed vulnerabilities.

## Scope Notes

Astra currently implements:

- OAuth and OIDC baseline flows
- a custom API key grant
- MFA with TOTP, email OTP, and WebAuthn baseline support
- OIDC federation with JWKS-backed validation

Astra does **not** currently claim:

- FAPI compliance
- SAML support
- LDAP/AD support

Those deferred items are tracked in the docs and roadmap as future decisions, not current security promises.
