# Authorization

Astra uses a hybrid authorization model:

- RBAC provides the baseline permission grant
- policy and attribute rules refine that grant
- decisions resolve to `ALLOW`, `DENY`, or `STEP_UP`

## Core Concepts

- roles and permissions
- authorization context
- subject, resource, and environment attributes
- policy rules with precedence
- assurance-aware decisions through `required_acr`

## Decision Precedence

1. explicit `DENY`
2. `STEP_UP` when stronger assurance is required
3. `ALLOW` when the permission exists and no stronger rule blocks it

## What Is Implemented

- role assignments and permission checks
- hybrid policy contracts
- in-memory policy store
- context-aware evaluation path
- session-aware step-up outcomes that integrate with MFA

## Access Policies

In addition to the core hybrid authorization model, Astra provides:
- **Astra Niyam (`astraauth-policy`)**: A dedicated Zanzibar-style relationship-based access control (ReBAC) system to evaluate transitive permissions dynamically.
- **Astra Mandal (`astraauth-tenancy`)**: Strict per-tenant policy isolation boundaries and request headers context bindings.
- **Graphical Console**: A visual DSL schema compiler, tuple playground, and permissions checker integrated directly inside **Astra Netra (`astraauth-admin-ui`)**.

See the [ReBAC Access Policies Guide](rebac-policies.md) and [Multi-Tenancy Isolation Guide](multi-tenancy.md) for detailed instructions.
