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

## What Is Not Implemented Yet

- a dedicated `astraauth-policy` package
- a graphical policy authoring UI
- a separate tenant-management package for policy isolation

The current baseline keeps policy behavior inside `astraauth-core`.
