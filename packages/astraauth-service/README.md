# Astra Sutra (`astraauth-service`)

Runtime composition and bootstrap layer for Astra.

## Best For

- running Astra from a configured runtime home
- composing the default session, MFA, plugin, federation, and observability stack
- operator workflows such as export/import, diagnostics, schema setup, and bootstrap management

## Responsibilities

- load `AuthConfig` from `DEFAULT_ASTRAAUTH_HOME`
- compose repositories, token manager, plugins, MFA, WebAuthn, and OIDC federation services
- expose runtime health and persistence reporting helpers
- apply bootstrap admin manifests during startup
- provide operator-facing config and bootstrap export/import helpers

## Typical Use

```python
from pathlib import Path
from astraauth_service import build_service_from_home, runtime_health_report

service = build_service_from_home(home=Path('.astraauth'))
health = runtime_health_report(home=Path(".astraauth"))
```

## Public API Areas

- runtime composition
- startup/bootstrap helpers
- export/import helpers
- diagnostics and observability snapshots
- OIDC audit access

## Startup Helpers

```python
from pathlib import Path
from astraauth_service import (
    build_service_from_home,
    ensure_runtime_schema,
    export_bootstrap_manifest,
    export_runtime_config,
    import_bootstrap_manifest,
    import_runtime_config,
    initialize_config_home,
    list_oidc_audit_records,
    runtime_health_report,
    runtime_inventory_report,
    validate_runtime_config,
    write_initial_admin_setup,
)
```

## Operator Workflows

```python
from pathlib import Path
from astraauth_service import (
    export_bootstrap_manifest,
    export_runtime_config,
    export_token_key_state,
)

home = Path(".astraauth")
export_runtime_config(Path("backups/config.json"), home=home)
export_bootstrap_manifest(Path("backups/bootstrap.json"), home=home)
export_token_key_state(Path("backups/token-keys.json"), home=home)
```

Notes:
- runtime config exports are plain JSON snapshots intended for operator portability
- bootstrap exports remain sensitive operator state and should be handled accordingly
- runtime state bundles can export and import both config and bootstrap state together
- token key exports are separate from the generic state bundle and should be handled as highly sensitive material

## Tests

```bash
uv run pytest -q packages/astraauth-service/tests
```
