# Astra Yantra (`astraauth-core`)

Framework-agnostic authentication and authorization domain logic for Astra.

## Best For

- teams composing their own auth runtime
- library-level integration without framework coupling
- direct access to configuration, token, session, MFA, and authorization primitives

## Includes

- OAuth/OIDC domain flows
- Token issuance and JOSE key handling
- Hybrid session model with refresh rotation
- Hybrid RBAC + ABAC authorization contracts
- MFA challenge and factor repositories
- Driver-first relational persistence contracts
- File-backed runtime configuration model

## Install

```bash
uv add astraauth-core
```

Optional extras:

```bash
uv add "astraauth-core[otp,postgres,mysql,sql-async,redis,zeromq]"
```

## Typical Use

```python
from astraauth_core.config import AuthConfig
from astraauth_core.authorization import AuthorizationDecision
from astraauth_core.ids import new_uuid7_str

config = AuthConfig.for_project(
    project_name="Astra",
    environment="dev",
    persistence_backend="sqlite",
)

request_id = new_uuid7_str()
assert isinstance(request_id, str)
```

## Public API Areas

- `astraauth_core.config`
- `astraauth_core.authorization`
- `astraauth_core.oauth`
- `astraauth_core.sessions`
- `astraauth_core.mfa`
- `astraauth_core.token`
- `astraauth_core.persistence`

## Related Packages

- `astraauth-service` / Astra Sutra for runtime composition
- `astraauth-adapters` / Astra Setu for framework mounts
- `astraauth-webauthn` / Astra Mudra for WebAuthn-specific contracts
- `astraauth-idp` / Astra Pramaan for enterprise federation

## Tests

```bash
uv run pytest -q packages/astraauth-core/tests
```
