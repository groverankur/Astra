# From Experiment to Platform: How Astra Became Python's Unified Authentication Layer

### One security domain. Five frameworks. Enterprise-grade RBAC, ABAC, Zanzibar ReBAC, step-up MFA, WebAuthn, and session auditing — in a single self-hosted Python library.

---

> **Pre-release notice:** Astra is currently in active pre-release development. The library is not yet published to PyPI. This article describes the architecture and capabilities of the platform. Installation is via source clone (see [Getting Started](#getting-started)). A PyPI release is planned once trusted publishing configuration and final hardening tasks are complete.

---

Authentication is one of those problems that feels "solved" until you actually try to implement it.

Suddenly you're juggling password hashing, JWTs, session stores, Role-Based Access Control, multi-tenancy, and enterprise integrations — all while trying to keep the developer experience smooth and the security model coherent. I know this because I've been there. A while back, I wrote [*Experimenting in Python: Building a React Better-Auth Inspired Authentication Library*](https://medium.com/@groverankur/experimenting-in-python-building-a-react-better-auth-inspired-authentication-library-284487b9e787) — an early proof-of-concept that asked a simple question:

> *What if Python had an authentication library as elegant, composable, and developer-friendly as Better Auth is for TypeScript?*

That experiment started with a wish list: email/password management, JWT and DB-backed sessions, multi-tenancy with scoped RBAC, TOTP/magic link 2FA, API key support, OIDC/OAuth2/SAML enterprise sign-on, and a plugin runtime so teams could extend without forking. The architecture was a gateway backed by pluggable stores and a composable plugin layer.

It was the right instinct. But a proof-of-concept sketch is very different from a production-grade library. **Astra is what that experiment grew into.**

> ✨ If you've ever hit this wall yourself — I'd love your feedback on the [GitHub repository](https://github.com/groverankur/Astra) while the API is still being shaped.

---

## The Fragmentation Tax

The Python ecosystem's approach to authentication has always been: pick your framework, pick your auth library, and pray they stay compatible.

- **Django** — `django-allauth`: Social auth, email verification, and account management out of the box. Highly opinionated and deeply Django-specific; customising internal logic is painful and the `Site` / `SocialApp` configuration is a common source of errors.
- **Flask** — `Flask-Login`: Session management only. Registration, password hashing, email verification, and everything else is entirely your problem to implement and secure correctly.
- **FastAPI** — `fastapi-users`: Users + JWT tokens, integrated tightly with FastAPI's dependency injection system. Works well for standard CRUD apps; quickly hits a ceiling when you need multi-tenancy, complex RBAC, or custom OAuth flows.
- **Litestar** — *(no dominant library)*: Ships an `AbstractSecurityConfig` guard abstraction, but you wire it to a token validator and user store yourself. The ecosystem gap is real.
- **Robyn** — *(no dominant library)*: A Rust-backed async framework built for raw throughput. Gives you HTTP handlers and nothing at the auth layer by design.
- **Generic** — `Authlib`: Low-level OAuth 2.0 and OpenID Connect primitives. Powerful but provides no user management, no session handling, and no authorization layer — it's plumbing, not a solution.

Each library is a fine solution *within its own world*. The moment you step outside that world — a monorepo with both a Django admin and a FastAPI microservice, a migration from Flask to Litestar, a new Robyn edge service that needs to share sessions with an existing FastAPI app — the fragmentation tax hits hard.

**You end up paying it in four currencies:**

1. **Duplicate security domain definitions.** Your password hashing strategy, your token TTLs, your role definitions — all defined twice, in two different paradigms. That's two places to audit, two places where drift becomes a vulnerability.
2. **Incompatible session stores.** `Flask-Login` uses the framework's session cookie. `fastapi-users` uses its own JWT. `django-allauth` has its own session model. Sharing a logged-in user across service boundaries requires custom serialization and trust assumptions that are easy to get subtly wrong.
3. **RBAC as an afterthought.** Flask-Login gives you nothing. django-allauth gives you `groups` and `permissions`, which are flat and Django-specific. fastapi-users gives you a `is_superuser` boolean. All three force you to hand-code role checks inline in your route handlers — precisely the pattern OWASP and security auditors warn against.
4. **Migration hell.** Moving off any of these libraries is a significant refactoring effort. Users' password hashes, active sessions, refresh tokens, and associated metadata are all baked into the library's own data model. There's no escape hatch.

---

## The "Just Use Auth0" Trap

When teams hit the ceiling of their auth library, the conventional wisdom is: offload to a managed IdP. Auth0. Clerk. WorkOS. Supabase Auth. These are excellent products and the right choice for many teams.

But they come with a specific set of trade-offs that are often underweighted in the initial decision:

- **Data residency and sovereignty.** Every authentication event, every user record, every session — stored in a third-party cloud. For teams in regulated industries, this is not negotiable.
- **Vendor lock-in.** Your session tokens, your MFA enrollment records, your social login links — all living in a proprietary data model. Migrating away from a managed IdP is substantially harder than migrating between self-hosted libraries.
- **Cost at scale.** Managed IdPs price per monthly active user (MAU). At 100k users it becomes a meaningful line item. At 1M it can cost more than the engineering team.
- **Customization ceilings.** Need step-up MFA that triggers specifically when a high-value action is performed — not just on login? Need ABAC rules that evaluate resource attributes against user attributes at the policy engine level? Many managed IdPs don't support this, and when they do, it's through proprietary rule DSLs that are painful to version-control and test.

The lesson from the JavaScript world is instructive. The same frustrations that drove the creation of **Better Auth** in 2024 — framework lock-in, monolithic design, the gap between "build from scratch" risk and "pay forever" managed service cost — exist in identical form in Python. Better Auth's core thesis was that TypeScript developers deserved a framework-agnostic, plugin-first, self-hosted auth library with modern primitives. That same thesis, applied natively to Python, is exactly what Astra delivers.

---

## What the "Just Roll It Yourself" Camp Gets Wrong

The alternative position is: authentication is not that hard, just implement it yourself. JWT + bcrypt + a sessions table. How hard can it be?

Harder than it looks. Here's what the research shows actually goes wrong:

**The JWT revocation problem.** JWTs are stateless by design, which means once issued, they remain valid until expiry. Session revocation — the ability to log a user out of all devices, or to kill a specific session when an anomalous IP change is detected — requires a blocklist or allowlist backed by a database or cache. Most hand-rolled implementations either don't implement this (leaving a security gap) or implement it incorrectly (allowing race conditions that defeat the entire purpose).

**The "none algorithm" vulnerability class.** Libraries like PyJWT before version 2.x accepted the `alg: none` header in tokens, allowing attackers to forge valid signatures. This class of bug affects any implementation that doesn't explicitly enforce algorithm constraints during verification. It's subtle enough that many teams only discover it during a security audit.

**The ABAC implementation pattern.** Research consistently shows that inline `if user.role == 'admin'` checks in route handlers — the approach every framework tutorial teaches — are inherently brittle. When the business logic for "who can delete this resource" lives scattered across fifty route handlers, you cannot audit it. You cannot reason about it. You cannot test it systematically. You need a centralized policy engine.

**WebAuthn ceremony complexity.** A correct FIDO2/WebAuthn implementation requires at minimum four backend endpoints (registration initiation, registration verification, authentication initiation, authentication verification), stateful challenge management, cryptographic CBOR parsing and attestation verification, and a credential database schema that correctly stores `credential_id`, `public_key`, and `signature_counter`. The signature counter alone — used to detect credential cloning — is a source of subtle bugs. Most DIY implementations skip it entirely.

**The Zanzibar problem.** Modern access control for multi-tenant applications with resource hierarchies (user → member of → team → owner of → project → contains → file) requires relationship-based evaluation. A flat RBAC model cannot express "Bob can edit this document because he's a member of the team that owns the project it belongs to." Implementing a Zanzibar-style ReBAC evaluator from scratch is a research-level engineering problem — Google Zanzibar itself was described in a [2019 research paper](https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/) as a system that handles trillions of access checks per second at global scale. The leading open-source implementations ([SpiceDB](https://github.com/authzed/spicedb), [OpenFGA](https://openfga.dev/), [Permify](https://permify.co/)) are written in Go and run as separate infrastructure components — adding operational complexity and a network hop to every authorization check. Projects like [KeyNetra](https://github.com/keynetra/keynetra) have begun closing this gap for Python, but integration into a complete auth stack still required significant glue work — until now.

---

## Why Astra Is Still Pre-Release (And Why That's Important Context)

Before diving into the technical architecture, it's worth being transparent: **Astra is in active pre-release development and is not yet available on PyPI.**

The codebase is in strong shape — 183 tests pass, the core Phase 8 baseline is implemented, and the full feature set described in this article is functional and runnable from source. What remains before a public release:

- Configuring trusted publishing on PyPI and running the first live release pipeline
- Continuing forward-migration of older SHA-256 password records to the Argon2-based default (security hardening)
- Expanding WebAuthn deployment guidance and deeper ceremony test coverage
- Improving documentation coverage, adding per-feature guides and a full API reference
- Adding polished end-to-end sample applications for each supported framework (FastAPI, Flask, Django, Litestar, Robyn)
- Final decisions on whether SAML and LDAP/AD support should become first-class packages
- Final decisions on the planned JS/React SDK surface area

This is the honest pre-release state. We're sharing the architecture and design decisions now precisely because we want the community's input before the API is frozen. Your feedback during this phase shapes what 1.0 looks like.

---

## Astra: Unified IAM That Grows With Your Architecture

Astra was built with a single organizing principle: **one security domain, any framework, any scale**.

Astra is a modular monorepo consisting of:

```text
astraauth (Astra Yantra, Astra Sutra, Astra Setu, Astra Pramaan, Astra Mudra)
├── astraauth.core       → Astra Yantra: Token management, session store, database persistence
├── astraauth.adapters   → Astra Setu: Framework adapters for FastAPI, Flask, Django, Litestar, Robyn
├── astraauth.service    → Astra Sutra: Runtime service coordinator and factory
├── astraauth.idp        → Astra Pramaan: Federated identity mapping (OIDC)
├── astraauth.webauthn   → Astra Mudra: FIDO2/WebAuthn passwordless verifications
├── astraauth-policy     → Astra Niyam: Zanzibar-style ReBAC policy engine
├── astraauth-tenancy    → Astra Mandal: Tenant isolation boundaries and context binding
├── astraauth-plugins    → Astra Tantra: Extensible plugin runtime and hook contracts
├── astraauth-cli        → Astra Dwaar: Operator key management and TUI dashboard
└── astraauth-admin-ui   → Astra Netra: Interactive browser admin dashboard with htmx views
```

### Plugin Architecture — Extend Without Forking

One of the original goals from that early experiment was a plugin runtime that lets teams add features without touching the library source. Astra delivers this through `astraauth-plugins` (Astra Tantra): a hook contract system where plugins register against well-defined lifecycle events — token issuance, session creation, MFA challenge, logout — and are resolved per-tenant at runtime.

This means you can write a custom rate-limiter plugin, a magic-link generator, an audit webhook emitter, or an IP reputation checker, and mount it alongside the core service without forking anything. The plugin registry is tenant-aware: tenant A can run a strict rate-limiting plugin while tenant B runs a relaxed one, all from the same service instance.

### Framework-Agnostic Mounting

Astra's security domain is defined once and mounted into **any** of five framework adapters: FastAPI, Flask, Django, Litestar, or Robyn. The `mount_oauth()` call is identical across all of them — only the import path changes:

```python
# FastAPI
from astraauth.adapters.fastapi.wiring import mount_oauth
mount_oauth(fastapi_app, service.adapter)

# Litestar (mounts routes as Litestar route handlers using @get/@post decorators)
from astraauth.adapters.litestar.wiring import mount_oauth
mount_oauth(litestar_app, service.adapter)

# Robyn (Rust-backed async framework — the same adapter works natively)
from astraauth.adapters.robyn.wiring import mount_oauth
mount_oauth(robyn_app, service.adapter)

# Flask, Django — identical pattern
from astraauth.adapters.flask.wiring import mount_oauth
from astraauth.adapters.django.wiring import mount_oauth
```

Every adapter registers the same set of endpoints: `/token`, `/authorize`, `/userinfo`, `/introspect`, `/logout`, `/mfa/challenge`, `/mfa/verify`, `/webauthn/register/start`, `/webauthn/register/finish`, `/webauthn/authenticate/start`, `/webauthn/authenticate/finish`, `/oidc/login/start`, `/oidc/callback`, `/.well-known/jwks.json`, and `/.well-known/openid-configuration`.

Critically, **the same `service` instance backs all of them**. A Django admin UI and a Litestar API can share sessions, roles, and token keys without any cross-service trust configuration.

### Stateful Session Lifecycle Management

Astra's session store is stateful by design. Every issued session has an explicit record that can be audited, inspected, and immediately revoked:

```python
# List all active sessions for a user — returns OS, browser, IP from metadata
active_sessions = service.sessions.list_active_for_subject(user_id)

# Instantly terminate a specific session (e.g., from a security panel)
service.sessions.revoke(session_id)

# Upgrade a session's assurance level after successful MFA verification
session.upgrade_authentication(target_acr=2, methods={"totp"})
service.sessions.save(session)
```

Tokens carry the session ID (`sid`) and version (`ver`) claims. A token whose session version doesn't match the current version in the store is rejected — eliminating the window between "user clicked logout" and "token actually expires."

### Centralized Policy Engine: RBAC, ABAC, and Zanzibar ReBAC

Astra ships three authorization models, composable in a single policy evaluation pass:

**RBAC (Role-Based):** Subjects hold roles; roles hold permission sets. The authorization engine resolves effective permissions by role graph traversal.

**ABAC (Attribute-Based):** Policy rules evaluate subject and resource attributes dynamically:

```python
from astraauth.core.authorization.models import PolicyRule, Decision

# "Users can edit documents in their own department"
policy_store.add_policy(PolicyRule(
    policy_id="dept-edit",
    tenant_id="acme",
    permission="documents.edit",
    effect=Decision.ALLOW,
    subject_match={"department": "${resource.department}"},
    resource_match={},
    environment_match={},
    reasons=("department_match",),
))
```

**ReBAC (Relationship-Based / Zanzibar-style, implemented by `astraauth-policy`, branded Astra Niyam):** Graph-based permission resolution, in-process, no external service required. Astra's ReBAC engine is inspired by the [Google Zanzibar paper](https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/) and the open-source work of the [KeyNetra project](https://github.com/keynetra/keynetra) — bringing Zanzibar-style relation tuples and DSL-defined schemas natively into the Python process:

```python
from astraauth_policy.parser import SchemaParser
from astraauth_policy.engine import CheckEngine
from astraauth_policy.store import RelationTuple, RelationTupleStore

# Define your relationship graph in a DSL that mirrors the Zanzibar paper
SCHEMA = """
definition user {}
definition team {
    relation owner: user
    relation member: user
    permission manage = owner
    permission access = manage | member
}
definition project {
    relation parent_team: team
    permission edit = parent_team->manage
    permission view = parent_team->access
}
"""

schema = SchemaParser.parse(SCHEMA)
store = RelationTupleStore()
store.tuples.append(RelationTuple(
    id="t1", tenant_id="acme",
    object_type="project", object_id="roadmap",
    relation="parent_team", subject_type="team", subject_id="platform"
))
store.tuples.append(RelationTuple(
    id="t2", tenant_id="acme",
    object_type="team", object_id="platform",
    relation="member", subject_type="user", subject_id="bob"
))

engine = CheckEngine(store=store, schema=schema)

# "Can Bob view this project?"
# Evaluates: project:roadmap.view -> parent_team:platform.access
# -> team:platform.member -> user:bob (found)
result = await engine.check(
    tenant_id="acme",
    subject_type="user", subject_id="bob",
    relation_or_permission="view",
    object_type="project", object_id="roadmap"
)
# result -> True
```

This is the authorization model used by Google Drive, GitHub, and Airbnb's permission systems — now available as a pure-Python, in-process library that requires no additional infrastructure and no extra network hops.

### Step-Up MFA — Contextual, Not Just a Login Gate

Most auth libraries treat MFA as a login-time gate. Astra implements MFA as a contextual assurance elevator — meaning it can be triggered *during an active session* in response to a high-risk action, not just at login:

```python
# Route handler: delete is a sensitive action requiring acr >= 2
@app.delete("/documents/{doc_id}")
async def delete_document(doc_id: str, session_id: str = Cookie(None)):
    session = service.sessions.get(session_id)

    if session.acr < 2:
        return JSONResponse({"error": "mfa_required", "factor": "email_otp"}, status_code=403)

    # acr >= 2, safe to proceed
    DOCUMENTS.remove(doc_id)
```

The frontend catches the `mfa_required` response, shows an OTP input modal, verifies the code against `/mfa/verify`, and retries the original request. The session assurance level is silently upgraded in-place. This is the pattern used in banking applications for wire transfers — and it's built in across all five framework adapters.

### WebAuthn and Passkeys — Ceremony Complexity Absorbed by the Library

Astra's WebAuthn module (`astraauth.webauthn`, branded Astra Mudra) encapsulates the entire FIDO2 ceremony: credential repository contracts, registration state management, authentication state management, and signature counter verification. The surface area you interact with is:

```python
# Registration ceremony
factor_id = service.begin_webauthn_registration(subject_id=user_id, tenant_id="acme")
# ... (browser completes WebAuthn ceremony with navigator.credentials.create()) ...
service.complete_webauthn_registration(factor_id=factor_id, attestation_response=attestation)

# Authentication ceremony
challenge = service.begin_webauthn_authentication(subject_id=user_id, tenant_id="acme")
# ... (browser completes WebAuthn ceremony with navigator.credentials.get()) ...
service.complete_webauthn_authentication(challenge_id=challenge.id, assertion_response=assertion)
```

The cryptographic heavy lifting — CBOR parsing, attestation format validation, signature verification, counter monotonicity checking — lives inside the library. All four required endpoints are automatically registered by `mount_oauth()` across all framework adapters.

### Litestar and Robyn: First-Class Citizens

Since Litestar and Robyn have no established auth library ecosystem, Astra treats them as first-class adapters rather than afterthoughts.

**Litestar** (`astraauth.adapters.litestar.wiring`): Routes are registered using Litestar's native `@get` / `@post` / `@route` decorators. Request normalization correctly handles Litestar's typed `Request[Any, Any, Any]` signature and its async `request.form()` parsing. CORS preflight is handled natively via `@route(..., http_method=["OPTIONS"])`. The response builder uses Litestar's `Response[str]` type with full header propagation.

**Robyn** (`astraauth.adapters.robyn.wiring`): Robyn's Rust-backed async runtime is fully supported. The adapter reads `request.ip_addr` for client IP extraction (Robyn's native attribute name), handles Robyn's async `form()` method, and serializes responses into Robyn's `Response` type via `json.dumps`. Every OAuth and WebAuthn endpoint is registered with `@app.post()` / `@app.get()` idioms native to Robyn. CORS preflight uses `@app.options("/{path:path}")`.

Both adapters expose the same Astra `OAuthHTTPAdapter` underneath — meaning if you use Robyn for your edge API and Litestar for your internal services, they share one policy store, one session store, and one key ring.

---

## Putting It All Together: A Real Flow

Here's how Astra's capabilities compose in a real scenario — Alice logging in, hitting a sensitive action, and accessing a resource gated by a ReBAC policy:

1. **Alice authenticates** via `POST /token` with her password. Astra hashes with Argon2id, issues a JWT carrying `sid`, `ver`, and `acr=1` claims, and records a session entry with her IP and user-agent.
2. **Alice tries to delete a document.** The route handler reads `session.acr`. It's `1` — below the required `2` for destructive actions. Astra returns `403 mfa_required`.
3. **Alice completes email OTP.** The frontend posts to `/mfa/verify`. Astra validates the code, upgrades the session's `acr` to `2` in the store, and increments the session `ver`. Any prior tokens are now invalid against the updated version.
4. **Alice retries the delete.** `acr=2` passes. Before executing, the route checks the ReBAC engine: does `user:alice` have `edit` permission on `document:quarterly-report`? The engine traverses: `document:quarterly-report → parent_project:roadmap → parent_team:platform → member:alice`. Access granted.
5. **Alice logs out from a second device.** The security panel calls `sessions.revoke(session_id)`. The session record is invalidated. Any token from that device is now permanently rejected — no expiry window required.

Each step uses a different Astra subsystem. None of them required you to write the underlying logic.

## The Multi-Tenant Architecture Gap

One final gap worth naming explicitly: **multi-tenancy in Python auth libraries is almost universally missing**.

`fastapi-users` has no tenant concept. `django-allauth` has `Site` objects, which are a legacy abstraction that doesn't map to modern SaaS tenancy. `Flask-Login` has nothing. Building multi-tenant auth yourself means threading a `tenant_id` through every session, every token claim, every authorization check — and hoping you don't forget it somewhere.

In Astra, tenancy (implemented by `astraauth-tenancy`, branded Astra Mandal) is a first-class primitive. Every session, token claim, role assignment, policy rule, and relation tuple carries a `tenant_id`. The authorization engine evaluates all checks in tenant scope. Session stores are tenant-aware. The plugin registry is per-tenant. You don't think about it because it's already there.

And when you're ready for production, swapping the in-memory store for a durable backend is a single configuration change — Astra's driver-first persistence layer supports **SQLite** for local development, **Postgres** for production, and **MySQL** for teams already running it in their stack.

---

## Getting Started

> **Note:** Astra is not yet published to PyPI. Install from source using `uv` (the recommended approach).

### Clone and Install

```bash
git clone https://github.com/groverankur/Astra.git
cd Astra

# Install the full workspace (recommended for contributors and evaluators)
uv sync --all-groups

# Or install individual packages with specific extras:
uv pip install -e "packages/astraauth-adapters[fastapi]"   # FastAPI adapter
uv pip install -e "packages/astraauth-adapters[flask]"     # Flask adapter
uv pip install -e "packages/astraauth-adapters[django]"    # Django adapter
uv pip install -e "packages/astraauth-adapters[asgi]"      # Generic ASGI / Litestar / Robyn
uv pip install -e "packages/astraauth-core[otp]"           # TOTP + email OTP MFA
uv pip install -e "packages/astraauth-core[postgres]"      # Postgres persistence
uv pip install -e "packages/astraauth-core[mysql]"         # MySQL persistence
```

### Minimal FastAPI Example (In-Memory, No Database)

```python
from fastapi import FastAPI
from astraauth.service import build_inmemory_service
from astraauth.core.authorization.models import Role
from astraauth.core.oauth.models import Subject, OAuthClient
from astraauth.adapters.fastapi.wiring import mount_oauth

app = FastAPI()
service = build_inmemory_service(default_plugins_enabled=True)

service.add_role(Role(name="user", permissions={"openid"}))
service.add_client(OAuthClient(
    client_id="my-app",
    allowed_tenants={"my-org"},
    client_type="public",
    auth_method="none",
    require_pkce=False,
))
service.add_subject_password(
    subject=Subject(subject_id="u1", tenants={"my-org"}, username="alice"),
    tenant_id="my-org",
    username="alice",
    password="correct-horse-battery-staple",
)

mount_oauth(app, service.adapter)
# /token, /authorize, /userinfo, /introspect, /logout are all live.
```

Swap the first import for `from astraauth.adapters.litestar.wiring import mount_oauth` or `from astraauth.adapters.robyn.wiring import mount_oauth` — and the rest of the code is identical. That's the point.

---

## The Bigger Picture

Python is increasingly the language of choice for high-stakes infrastructure: fintech backends, healthcare APIs, enterprise SaaS products. These systems need IAM that matches their ambition.

The existing library landscape — framework-specific, RBAC-minimal, session-revocation-optional, MFA-bolted-on — was designed for simpler times. The alternative (managed SaaS IdPs) trades control, data sovereignty, and long-term cost for convenience.

Astra is the third path: a self-hosted, framework-agnostic, enterprise-grade IAM platform that ships as a Python library, deploys in your infrastructure, and scales with your architecture.

---

## References

- [Experimenting in Python: Building a React Better-Auth Inspired Authentication Library](https://medium.com/@groverankur/experimenting-in-python-building-a-react-better-auth-inspired-authentication-library-284487b9e787) — the original proof-of-concept that became the seed for Astra
- [Google Zanzibar: Google's Consistent, Global Authorization System](https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/) — the foundational paper behind ReBAC
- [KeyNetra](https://github.com/keynetra/keynetra) — open-source Zanzibar-style ReBAC implementation for Python, whose design informed Astra's policy engine
- [SpiceDB](https://github.com/authzed/spicedb) — Go-based Zanzibar implementation (referenced for comparison with Astra's infrastructure-free Python alternative)
- [OpenFGA](https://openfga.dev/) — CNCF Zanzibar-inspired authorization service
- [Better Auth](https://better-auth.com/) — TypeScript's framework-agnostic auth library that validated the design direction Astra follows for Python
- [OWASP Top 10: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) — industry rationale for centralized policy engines over inline role checks
- [Astra GitHub Repository](https://github.com/groverankur/Astra)

---

**✨ Star the project on [GitHub](https://github.com/groverankur/Astra)** and join the conversation. We're building the IAM platform the Python ecosystem deserves — and we want your input before 1.0 ships.
