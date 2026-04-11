# Astra Pramaan (`astraauth-idp`)

OIDC federation baseline and external identity contracts for Astra.

## Best For

- implementing OIDC login and callback handling in a custom runtime
- managing identity links, group-to-role mapping, and claim-to-attribute mapping
- persisting federation audit data outside the full Astra service composition layer

## Current Scope

- OIDC federation baseline
- External identity linking
- Group-to-role mapping
- Claim-to-attribute mapping
- Federation audit persistence
- OIDC login state and callback contracts

OIDC is part of the baseline package surface here, so there is no separate
runtime extra for it at the moment.

## Optional Extension Tracks

- SAML
- LDAP/AD

These remain optional and are not required for the current baseline.

## Typical Use

```python
from astraauth_idp import (
    OIDCProviderConfig,
    begin_oidc_login,
    build_authorization_url,
)

provider = OIDCProviderConfig(
    provider_id="example",
    issuer="https://idp.example.com",
    client_id="client-id",
    client_secret="client-secret",
    redirect_uri="https://app.example.com/callback",
)
```

This package is often consumed through `astraauth-service`, but its models,
repositories, and callback contracts are usable directly.

## Public API Areas

- provider and metadata models
- login-state repositories
- identity-link repositories
- mapping repositories
- callback and federation services
- federation audit repositories

## Deferred Tracks

- SAML federation
- LDAP/AD sync or auth bridge

## Tests

```bash
uv run pytest -q packages/astraauth-idp/tests
```
