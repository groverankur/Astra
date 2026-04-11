# Astra Dwaar (`astraauth-cli`)

Operational CLI for Astra.

## Install

```bash
pip install astraauth-cli==0.5.1
```

Optional extras:

```bash
pip install "astraauth-cli[interactive,tui]==0.5.1"
```

## Best For

- runtime-home setup
- backup/export/import workflows
- operator diagnostics
- key management
- bootstrap admin setup and lockdown

## Core Command Groups

- setup and config
  - `astra config-home`
  - `astra config-init`
  - `astra validate-config`
  - `astra schema-ensure`
- runtime inspection
  - `astra health`
  - `astra runtime-inventory`
  - `astra persistence-info`
  - `astra doctor`
  - `astra observability`
- backup and recovery
  - `astra config-export`
  - `astra config-import`
  - `astra state-export`
  - `astra state-import`
  - `astra backup-verify`
- key management
  - `astra key-jwks`
  - `astra key-export`
  - `astra key-import`
  - `astra key-rotate`
- bootstrap and audits
  - `astra init-admin`
  - `astra bootstrap-show`
  - `astra bootstrap-lockdown`
  - `astra bootstrap-export`
  - `astra bootstrap-import`
  - `astra oidc-audit`
  - `astra admin-audit`
- interactive modes
  - `astra wizard`
  - `astra admin-ui`

## Typical Use

```bash
uv run astra config-init --home .astraauth --environment dev --persistence-backend sqlite
uv run astra validate-config --home .astraauth
uv run astra schema-ensure --home .astraauth --json
uv run astra config-export --home .astraauth --output backups/config.json
uv run astra health --home .astraauth --json
uv run astra --help
```

## Notes

- `config-export` writes plain JSON, and `config-import` validates then re-encrypts values by default when saving into runtime home
- `state-export` and `state-import` bundle `config.json` and `bootstrap.json` together for operator backup and handoff workflows
- `key-export` and `key-import` manage persisted runtime key state separately from the generic state bundle
- `wizard` provides interactive setup flow
- `admin-ui` provides a terminal admin shell for common operator actions, with optional Textual TUI support when installed
- `init-admin` writes `bootstrap.json` for first-run runtime setup
- `bootstrap-show` inspects the current bootstrap manifest without building the runtime
- `bootstrap-lockdown` disables future setup-token issuance and clears remaining setup tokens
- `bootstrap-export` and `bootstrap-import` support operator backup/restore workflows; bootstrap exports should be treated as sensitive because they can contain initial passwords
- `runtime-inventory` shows configured OIDC providers, registered plugins, tenant plugin enablement, and bootstrap-admin count
- `oidc-audit` reads persisted federation audit records through the runtime composition layer
- `key-rotate` persists rotated keys back into the runtime home

## Tests

```bash
uv run pytest -q packages/astraauth-cli/tests
```
