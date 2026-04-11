# Configuration

Astra runtime configuration is centered on the runtime home directory, usually `.astraauth/`.

## Runtime Home Layout

Typical files you will see:

- `config.json`
  - main runtime configuration
- `bootstrap.json`
  - bootstrap admin and setup-token state
- `secrets/settings.key`
  - encryption key for protected runtime values
- `secrets/token-keys.json`
  - encrypted token-key state managed by the runtime helpers
- `logs/astraauth-events.log`
  - structured runtime event log
- `logs/observability-metrics.json`
  - persisted counters and observability snapshot data
- `admin-actions.json`
  - encrypted browser admin action audit trail

## Loading Model

The current config model lives in `astraauth_core.config.AuthConfig` and loads from:

1. built-in defaults
2. `config.json`
3. `.env`
4. process environment variables prefixed with `ASTRAAUTH_`

## Runtime Config Example

```json
{
  "project_name": "Astra",
  "environment": "dev",
  "issuer": "https://auth.example.local",
  "persistence": {
    "default_database": {
      "backend": "sqlite",
      "mode": "sync",
      "database": ".astraauth/data/astra.db"
    },
    "auto_create_schema": true
  },
  "observability": {
    "service_name": "astraauth",
    "structured_logging_enabled": true,
    "metrics_enabled": true,
    "correlation_header_name": "X-Correlation-ID"
  }
}
```

## CLI-Friendly Workflows

Initialize:

```bash
uv run astra config-init --home .astraauth --environment dev --persistence-backend sqlite
```

Export/import:

```bash
uv run astra config-export --home .astraauth --output backups/config.json
uv run astra config-import --home .astraauth --input backups/config.json
```

Validate:

```bash
uv run astra validate-config --home .astraauth
uv run astra doctor --home .astraauth --json
```

## Persistence Backends

Implemented and supported in code:

- SQLite
- PostgreSQL
- MySQL

The persistence layer uses driver-first repositories with sync and async support where implemented.

## Bootstrap Security Notes

`bootstrap.json` is safer than the early prototype, but it is still sensitive operator state.

Current protections:

- bootstrap admin passwords are stored as hashes, not plaintext
- setup tokens are short-lived and hashed at rest
- setup token issuance can be locked permanently with `astra bootstrap-lockdown`

## OIDC Provider Configuration

OIDC providers are configured through the `idp` section of `AuthConfig` and consumed by `astraauth-service`. OIDC is the only enterprise federation protocol implemented in the current baseline.

## Deferred Configuration Areas

These do not exist yet as first-class packages or schemas:

- policy authoring package
- tenancy package
- observability package
- SAML provider config
- LDAP/AD bridge config
