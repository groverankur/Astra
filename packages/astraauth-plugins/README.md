# Astra Tantra (`astraauth-plugins`)

Plugin runtime, tenant enablement registry, and extension contracts for Astra.

## Includes

- Deterministic hook execution
- Hook timeout and failure classification
- Tenant plugin registry
- Endpoint extension helpers
- Built-in geo and risk signal plugins

## Public API

```python
from astraauth_plugins import PluginRuntime, RiskSignalPlugin

runtime = PluginRuntime()
runtime.register(RiskSignalPlugin(max_risk_score=70))
runtime.enable_for_tenant(tenant_id="tenant-1", plugin_name="risk")
```

Use `astraauth-service` when you want the runtime pre-wired into a working auth stack.

## Package Shape

- `contracts.py`: hook and extension contracts
- `runtime.py`: plugin registration, tenant enablement, and hook execution
- `builtin_plugins.py`: release-facing built-in plugins shipped with the package
- `examples.py`: compatibility shim for older example-style imports

## Built-in Plugins

- `GeoSignalPlugin`
  - blocks configured countries
  - contributes a simple health endpoint
- `RiskSignalPlugin`
  - enforces a risk score threshold
  - can hint that MFA should be challenged

Backward-compatible aliases remain available:

- `GeoPlugin` -> `GeoSignalPlugin`
- `RiskPlugin` -> `RiskSignalPlugin`

## Tests

```bash
uv run pytest -q packages/astraauth-plugins/tests
```
