# Astra Tantra (`astraauth-plugins`)

Plugin runtime, tenant enablement registry, and extension contracts for Astra.

## Includes

- Deterministic hook execution
- Hook timeout and failure classification
- Plugin trust policy with allowlists, version ranges, digest/source checks, and signed manifests
- Tenant-level plugin enablement policy
- Lifecycle audit records for register, enable, disable, trust denials, signature failures, and timeouts
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

Production deployments should configure explicit trust policy before registering third-party plugins:

```python
from astraauth_plugins import PluginManifest, PluginRuntime, PluginTrustPolicy, sign_plugin_manifest

policy = PluginTrustPolicy(
    allowed_plugins=frozenset({"risk"}),
    allowed_versions={"risk": ">=1.0,<2.0"},
    allowed_digests={"risk": frozenset({"sha256:plugin-package-digest"})},
    allowed_source_fingerprints={"risk": frozenset({"pkg:risk@sha256:source"})},
    tenant_allowed_plugins={"tenant-1": frozenset({"risk"})},
    require_signatures=True,
    trusted_public_keys=(trusted_public_key_pem,),
    max_timeout_ms=500,
)

manifest = sign_plugin_manifest(
    PluginManifest(
        name="risk",
        version="1.2.0",
        digest="sha256:plugin-package-digest",
        hooks=("auth.pre_authorize",),
        endpoints=("/auth/ext/risk/health",),
        requested_permissions=("tenant.signal.read",),
        source_fingerprint="pkg:risk@sha256:source",
    ),
    plugin_signing_private_key_pem,
)

runtime = PluginRuntime(trust_policy=policy)
runtime.register(RiskSignalPlugin(max_risk_score=70), manifest=manifest)
runtime.enable_for_tenant(tenant_id="tenant-1", plugin_name="risk")
```

Unsigned manifests are allowed only when `require_signatures=False`. If a manifest carries a signature, it is verified against `trusted_public_keys`. Plugin-provided `timeout_ms` values are capped by `max_timeout_ms`; timed-out hooks and endpoints return promptly to the caller and emit failed audit records.

Use `astraauth-service` when you want the runtime pre-wired into a working auth stack.

## Package Shape

- `contracts.py`: hook and extension contracts
- `runtime.py`: plugin registration, trust validation, tenant enablement, and hook execution
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
