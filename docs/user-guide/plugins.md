# Plugins

Astra includes a tenant-aware plugin runtime for extending the platform without changing the core packages directly.

## Implemented Plugin Capabilities

- tenant plugin registry
- in-memory and relational registry persistence
- hook contracts and runtime execution
- timeout and isolation policy
- endpoint extension materialization into framework routers
- built-in geo and risk signal plugins for baseline extension examples

## Good Uses For Plugins

- tenant-specific mapping logic
- endpoint extensions
- post-auth hooks
- custom audit or notification behavior

## Built-In Plugin Baseline

`astraauth-plugins` ships with two simple built-in plugins:

- `GeoSignalPlugin`
- `RiskSignalPlugin`

These are intentionally small, production-shaped examples of the extension
contract, and they remain available through the older compatibility aliases
`GeoPlugin` and `RiskPlugin`.

## What Plugins Are Not

Plugins are not the right place to hide foundational protocol implementations such as SAML, LDAP bind logic, or core persistence. Those belong in dedicated modules if they are ever added.
