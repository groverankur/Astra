# Plugins

Astra includes a tenant-aware plugin runtime for extending the platform without changing the core packages directly.

## Implemented Plugin Capabilities

- tenant plugin registry
- in-memory and relational registry persistence
- hook contracts and runtime execution
- timeout and isolation policy
- endpoint extension materialization into framework routers
- endpoint execution reports and runtime audit records
- built-in geo and risk signal plugins for baseline extension examples

## Good Uses For Plugins

- tenant-specific mapping logic
- endpoint extensions
- post-auth hooks
- custom audit or notification behavior

## Runtime Boundaries

- plugin endpoint routes must stay under `/auth/ext/<plugin-name>/...`
- plugin endpoints cannot override core Astra routes
- duplicate plugin route and method claims are rejected during endpoint materialization
- hook and endpoint execution both run behind timeout/error boundaries
- endpoint failures are masked into safe HTTP responses instead of bubbling raw exceptions through the web framework
- runtime audit records capture hook and endpoint execution status, duration, and error classification
- runtime-home deployments persist recent plugin audit records so service and admin diagnostics can inspect them later

## Built-In Plugin Baseline (Astra Tantra)

`astraauth-plugins` ships with two simple built-in plugins:

- `GeoSignalPlugin`
- `RiskSignalPlugin`

These are intentionally small, production-shaped examples of the extension contract, and they remain available through the older compatibility aliases `GeoPlugin` and `RiskPlugin`.

---

## 🛠️ Implementing a Custom Plugin

Custom tenant plugins subclass or define interfaces adhering to core plugin contracts under `astraauth.plugins.contracts`. Below is an example of a custom plugin that extends route handlers and hooks:

```python
from typing import Any
from dataclasses import dataclass
from astraauth.plugins.contracts import HookName, EndpointExtension, TableExtension

@dataclass(frozen=True)
class CustomAuditPlugin:
    name: str = "custom_audit"
    order: int = 20

    def hooks(self) -> dict[HookName, Any]:
        return {
            "auth.pre_authenticate": self._pre_auth_hook,
        }

    def register_endpoints(self) -> tuple[EndpointExtension, ...]:
        return (
            EndpointExtension(
                self.name, 
                "/auth/ext/custom_audit/ping", 
                ("GET",), 
                self._ping_handler
            ),
        )

    def register_tables(self) -> tuple[TableExtension, ...]:
        return ()

    def _ping_handler(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {"status": "alive", "plugin": self.name}

    def _pre_auth_hook(self, payload: dict[str, Any]) -> dict[str, Any]:
        # Custom logging or user validation checks
        return {"custom_audit_logged": True}
```

---

## What Plugins Are Not

Plugins are not the right place to hide foundational protocol implementations such as SAML, LDAP bind logic, or core persistence. Those belong in dedicated modules if they are ever added.
