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
- `secrets/settings-key-metadata.json`
  - active settings-key ID, creation time, rotation state, and algorithm
- `secrets/token-keys.json`
  - encrypted token-key state managed by the runtime helpers
- `logs/astraauth-events.log`
  - structured runtime event log
- `logs/observability-metrics.json`
  - persisted counters and observability snapshot data
- `admin-actions.json`
  - encrypted browser admin action audit trail

## Loading Model

The current config model lives in `astraauth.core.config.AuthConfig` and loads from:

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
uv run astra security --home .astraauth --json
```

Rotate the config-encryption key:

```bash
uv run astra config-key-rotate --home .astraauth
```

Rotation decrypts the existing config with the active key, creates a new key,
re-encrypts the config, writes active-key metadata, and retains metadata for the
retired key. It does not retain the retired key material.

## Local Key Custody

- On POSIX systems, Astra creates runtime-home and secrets directories with
  mode `0700`, and config, key, export, metadata, metrics, and security-log
  files with mode `0600`.
- `astra doctor` and `astra security` report missing key metadata, stale keys,
  unencrypted config values, and weak POSIX permissions.
- On Windows, POSIX mode bits do not provide equivalent protection. Diagnostics
  emit `windows_acl_review_required`; restrict the runtime home and secrets
  directory ACLs to the service account and required administrators.
- Treat exported config, state bundles, bootstrap artifacts, and token-key
  exports as sensitive even when encrypted.

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
