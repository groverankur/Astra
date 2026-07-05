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

## Built-In Plugin Baseline

`astraauth-plugins` ships with two simple built-in plugins:

- `GeoSignalPlugin`
- `RiskSignalPlugin`

These are intentionally small, production-shaped examples of the extension
contract, and they remain available through the older compatibility aliases
`GeoPlugin` and `RiskPlugin`.

## What Plugins Are Not

Plugins are not the right place to hide foundational protocol implementations such as SAML, LDAP bind logic, or core persistence. Those belong in dedicated modules if they are ever added.
