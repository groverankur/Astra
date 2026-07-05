# OIDC Federation

OIDC is the enterprise federation baseline for Astra.

## Implemented

- provider configuration
- discovery
- authorization-code login initiation
- callback handling
- login state and nonce handling
- JWKS-backed ID token verification
- identity linking
- group-to-role mapping
- claim-to-attribute mapping
- local Astra session issuance after successful federation
- federation audit persistence

## Deferred By Decision

These are not part of the current production-ready baseline:

- SAML federation
- LDAP/AD sync or auth bridge

## Runtime Submodules

- contracts and persistence: `astraauth.idp`
- runtime composition: `astraauth.service`
- adapter endpoints: `astraauth.core` + `astraauth.adapters`

## What To Expect

If you need enterprise federation today, OIDC is the supported path. If a concrete customer or deployment requires SAML or LDAP/AD later, they should be introduced as dedicated modules instead of placeholder packages.
