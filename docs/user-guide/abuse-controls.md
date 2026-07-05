# Abuse Controls and Plugin Runtime Safety

Astra includes baseline abuse controls for repeated credential failures and a constrained plugin runtime model for extension safety.

Runtime adapters also support an origin policy for browser-facing deployments.
Configure `AdapterOriginPolicy` on ASGI, FastAPI, Flask, Django, Robyn, or
Litestar mounts to reject unsafe state-changing requests from untrusted origins
and to emit CORS preflight headers only for allowed origins.

## What Is Throttled

The runtime adapter applies throttling to repeated failures on:

- `/token`
- MFA verification
- WebAuthn authentication finish

The admin UI applies throttling to:

- repeated operator login failures
- repeated sensitive operator actions such as config initialization and key rotation

Throttled responses return:

- HTTP `429`
- a `Retry-After` header

## Storage Model

Throttle state is backed by:

- in-memory storage for in-memory service deployments
- shared relational storage when the runtime uses shared persistence
- a local shared SQLite-backed store for the admin UI under the runtime home

This means:

- multi-process workers can enforce shared limits when they point at the same runtime persistence
- local development still works without extra infrastructure

## Diagnostics

Service and admin diagnostics now expose:

- throttle storage kind
- tracked bucket counts
- currently blocked bucket counts
- redacted bucket fingerprints for active blocks

Bucket identities are not exposed directly. Diagnostics show the throttle scope, such as `oauth-token` or `mfa-verify`, plus a short fingerprint.

## Plugin Runtime Safety

Plugin hook and endpoint execution is guarded by:

- namespace restrictions for plugin endpoints
- duplicate route and method collision checks
- timeout boundaries
- validation/runtime failure classification
- safe HTTP masking for plugin endpoint failures

Plugin endpoint failures return safe framework responses instead of leaking raw exceptions back to callers.

## Plugin Audit Trail

Plugin execution diagnostics include:

- hook and endpoint execution type
- status
- duration
- fail-open or fail-closed mode
- error classification when applicable

When Astra runs from a runtime home, recent plugin audit records are persisted to:

- `.astraauth/logs/plugin-runtime-audit.jsonl`

The service package can surface these records through `runtime_security_report(...)`, and the admin UI exposes them in its diagnostics dashboard and `/api/security`.

The CLI exposes the same operator report through:

```bash
astra security --home .astraauth --json
```

Plugin runtime audit records can be exported directly through:

```bash
astra plugin-audit --home .astraauth --json
astra plugin-audit --home .astraauth --plugin-name geo --status failed --json
```

## Operator Guidance

- Keep shared persistence enabled in production so runtime throttling is enforced across workers.
- Review blocked-bucket counts if login or verification failures suddenly spike.
- Review plugin audit logs when enabling new tenant plugins or debugging extension failures.
- Treat plugin endpoint code as trusted runtime code. The runtime adds boundaries, but it does not make unsafe plugin logic safe by itself.

## Investigating a Spike in Blocked Throttle Buckets

Use this sequence when blocked-bucket counts rise unexpectedly:

1. Confirm the scope of the spike.
   - `astra security --home .astraauth --json`
   - check `runtime_throttle.blocked_bucket_count`
   - check which scopes are blocked, such as `oauth-token`, `mfa-verify`, or `webauthn-finish`

2. Separate runtime traffic from operator traffic.
   - runtime signals appear under `runtime_throttle`
   - admin operator signals appear under `admin_ui_throttle`
   - if only admin UI buckets are blocked, investigate operator workflows first

3. Correlate with event volume.
   - inspect `astra observability --home .astraauth --json`
   - review counters and recent admin actions

4. Check plugin behavior if auth decisions recently changed.
   - `astra plugin-audit --home .astraauth --json`
   - filter to failures or a specific plugin if needed
   - look for repeated validation or timeout failures that may be amplifying retries

5. Review application and federation context.
   - `astra admin-audit --home .astraauth --json`
   - `astra oidc-audit --home .astraauth --tenant-id <tenant> --json`

6. Decide whether this is abuse, user error, or system drift.
   - abuse usually shows repeated blocked credential scopes from the same small set of buckets
   - user error often shows isolated login or MFA failures after a rollout
   - system drift often shows plugin failures, OIDC callback issues, or sudden verification mismatches

7. Remediate deliberately.
   - fix the underlying auth, MFA, plugin, or configuration problem
   - do not disable throttling as a first response
   - if you need to clear state, do it only after understanding whether the source is malicious or accidental
