# Package-by-Package Context, Architecture & Workflows

This document breaks down the System Context, Module Architecture, and sequential Workflows for each of the active packages in the Astra monorepo.

---

## 1. Astra Yantra (Core Module / `astraauth.core`)

The absolute foundation containing framework-agnostic domain models, settings validation, and cryptographic/policy primitives.

### System Context
```mermaid
graph LR
    Core["astraauth-core / astraauth.core"]
    DB[("Relational Database")]
    Crypt["cryptography / joserfc / pwdlib"]
    Policies["Policy Configs (RBAC + ABAC)"]
    
    Core --> DB
    Core --> Crypt
    Core --> Policies
```

### Module Architecture
*   `config/settings.py`: Resolves settings utilizing `pydantic-settings` (database configurations, token expirations, CORS rules, throttling thresholds).
*   `security/throttling.py`: Controls login and verification rate limits using sliding windows (in-memory or Redis).
*   `persistence/relational.py` & `repositories/`: Centralizes unified SQL connection queries for SQLite, PostgreSQL, and MySQL.
*   `oauth/`: Implements client credentials, PKCE checks, token hashing, API keys (using constant-time timing protection), and Argon2id password hashing.
*   `authorization/`: Evaluation rules matching user metadata and attributes (ABAC) to enforce scopes (`ScopePolicy`).

### Core Workflow: Access Token Verification
```mermaid
sequenceDiagram
    participant Caller as Calling Service / Middleware
    participant Core as astraauth.core
    participant JWKS as JWKS Store
    participant DB as Persistence Engine

    Caller->>Core: Verify Token Signature (JWT)
    Core->>JWKS: Fetch Cached Public Key (JWKS)
    JWKS-->>Core: Public Key Returned
    Core->>Core: Cryptographically Verify Signature & Expiration
    
    alt Signature Valid
        Core->>DB: Query Session Active Status & Tenant (tid)
        DB-->>Core: Session Active
        Core->>Core: Evaluate ABAC Rules (Tenant & Scope policies)
        Core-->>Caller: Returns Verified Claims (User ID, Roles, Tenant)
    else Signature Invalid
        Core-->>Caller: Raise TokenValidationError
    end
```

---

## 2. Astra Sutra (Service Module / `astraauth.service`)

The runtime composition layer that bootstraps application setups, connection pools, structured logging, and observability.

### System Context
```mermaid
graph TD
    Service["astraauth-service / astraauth.service"]
    Config["Runtime Settings File"]
    Logger["Structured Logging (Redacted)"]
    Pools["DB Connection Pools"]
    CorePkg["astraauth.core"]

    Service --> Config
    Service --> Logger
    Service --> Pools
    Service --> CorePkg
```

### Module Architecture
*   `factory.py`: The dependency injector. Builds the repository engine, links the correct database pool, configures the event bus, and injects runtime services.
*   `startup.py`: Coordinates database schema updates, manages startup lifecycles, and listens for configuration change triggers.
*   `observability.py`: Manages structured log JSON outputs and telemetry context (correlation ID injection).
*   `redaction.py`: Exposes helper filters that intercept logs to redact passwords, hashes, keys, and challenge pins.

### Core Workflow: Configuration Hot-Reload
```mermaid
sequenceDiagram
    participant Operator as Admin UI / CLI
    participant Service as astraauth.service
    participant Core as astraauth.core
    participant Pools as Database Connection Pools

    Operator->>Service: Trigger Settings Reload (e.g. key rotation or DB shift)
    Service->>Service: Read updated configuration file
    Service->>Core: Re-validate configuration model with Pydantic
    
    alt Config Valid
        Service->>Pools: Terminate active connection pools gracefully
        Service->>Pools: Initialize new connection pools with updated configs
        Service->>Core: Apply updated JWKS keys and cache rules
        Service-->>Operator: Return Status 200 (Success)
    else Config Invalid
        Service-->>Operator: Raise ConfigurationError (Roll back changes)
    end
```

---

## 3. Astra Setu (Adapters Module / `astraauth.adapters`)

Framework wrappers providing pre-built route handlers, session managers, and middleware hooks for major Python runtimes.

### System Context
```mermaid
graph LR
    WebFrameworks["FastAPI / Flask / Django / Robyn / Litestar"]
    Adapter["astraauth-adapters / astraauth.adapters"]
    Core["astraauth-core / astraauth.core"]

    WebFrameworks --> Adapter
    Adapter --> Core
```

### Module Architecture
*   `base.py`: Defines the parent `AstraBaseMiddleware` protocol.
*   `http_types.py`: Translates framework-specific request variables into unified `HttpRequest` and `HttpResponse` dataclasses.
*   `extensions.py`: Route builder helpers to auto-inject login, logout, and token endpoints into target application routers.
*   `fastapi/`, `flask/`, `django/`, `litestar/`, `robyn/`, `asgi/`: Specific controller submodules mapping framework endpoints to AstraAuth core hooks.

### Core Workflow: FastAPI Dependency Authentication Check
```mermaid
sequenceDiagram
    actor Client as External Client
    participant API as FastAPI Application Route
    participant Adapter as fastapi_adapter
    participant Core as astraauth.core

    Client->>API: GET /protected-resource (Cookie / Authorization Header)
    API->>Adapter: Check Dependency (e.g. Depends(require_user(scope="admin")))
    Adapter->>Adapter: Extract credentials -> Translate to HttpRequest
    Adapter->>Core: Call token verification engine
    
    alt Verification Success
        Core-->>Adapter: Returns User Claims
        Adapter-->>API: Inject authenticated User Context
        API-->>Client: Return HTTP 200 (Resource Data)
    else Verification Failure
        Core-->>Adapter: Raise AuthenticationError
        Adapter-->>Client: Return HTTP 401 Unauthorized
    end
```

---

## 4. Plugins Engine (`astraauth.plugins`)

The execution coordinator that loads, registers, and sandboxes tenant-specific custom hooks (middleware) with timeout bounds.

### System Context
```mermaid
graph TD
    Plugins["astraauth.plugins (Engine)"]
    Registry["Relational Plugin Registry"]
    Sandbox["Async Timeout Task Sandbox"]
    Events["Event Bus Auditing"]

    Plugins --> Registry
    Plugins --> Sandbox
    Plugins --> Events
```

### Module Architecture
*   `contracts.py`: Exposes base execution schemas and parameters that custom tenant plugins must conform to.
*   `runtime.py`: Implements the plugin loading pipeline, handles error boundaries, and runs scripts under strict async timeout conditions.

### Core Workflow: Sandboxed Pre-Authentication Plugin Exec
```mermaid
sequenceDiagram
    participant AuthEngine as Authentication Pipeline (Core)
    participant Runtime as Plugins Runtime (Tantra)
    participant Task as Async Sandbox Task
    participant Logger as Audit Event Log

    AuthEngine->>Runtime: Trigger Hook: "auth.pre_authenticate" (Payload)
    Runtime->>Runtime: Read Tenant Registry configuration
    Runtime->>Task: Create sandboxed Task (Timeout: 500ms)
    
    alt Task completes under 500ms
        Task-->>Runtime: Returns updated Auth Payload (Valid)
        Runtime->>Logger: Write success audit record
        Runtime-->>AuthEngine: Continue authentication pipeline
    else Task Times Out / Raises Error
        Task-->>Runtime: TaskTimeout / ExecutionException
        Runtime->>Logger: Write CRITICAL audit record (Plugin Failure)
        
        alt fail_closed is True
            Runtime-->>AuthEngine: Raise PluginExecutionError (Aborts Auth)
        else fail_closed is False
            Runtime-->>AuthEngine: Bypass error, continue with fallback
        end
    end
```

---

## 5. Astra Pramaan (Identity Provider / `astraauth.idp`)

Coordinates identity linking, user mapping, and token validation for federated identity setups (OIDC).

### System Context
```mermaid
graph LR
    IdP["astraauth-idp / astraauth.idp"]
    ExtOIDC["Upstream OIDC Providers (Okta/Google)"]
    Core["astraauth-core / astraauth.core"]
    Audit["Federation Audit Logger"]

    IdP --> ExtOIDC
    IdP --> Core
    IdP --> Audit
```

### Module Architecture
*   `store.py`: Exposes interfaces to persist linked identity configurations and callback states.
*   `sql_store.py`: Concrete SQLAlchemy mapping logic for identity linking, state caching, and OIDC logs.
*   `models.py`: Defines schemas for external credentials, role mapping rules, and identity providers.
*   `services.py`: Dispatches JWKS verification, maps claims, links user accounts, and builds OIDC configuration discovery templates.

### Core Workflow: External OIDC Authentication & Account Mapping
```mermaid
sequenceDiagram
    actor User as User Agent
    participant Adapter as Adapters
    participant IDP as astraauth.idp
    participant Okta as Upstream Okta OIDC
    participant Core as astraauth.core

    User->>Adapter: GET /auth/federation/callback?code=xxx&state=yyy
    Adapter->>Pramaan: Handle Callback
    Pramaan->>Pramaan: Verify State validation
    Pramaan->>Okta: Exchange Code for Access/ID Token
    Okta-->>Pramaan: Return Tokens (ID Token)
    Pramaan->>Pramaan: Verify ID Token signature using Okta public JWKS
    Pramaan->>Pramaan: Extract profile claims (Email, groups)
    Pramaan->>Core: Query linked identity mapping
    
    alt Identity Exists & Linked
        Core-->>Pramaan: Return linked internal User Record
    else Identity Exists but Not Linked
        Pramaan->>Core: Auto-link email matching user / Create new mapped user
        Core-->>Pramaan: Return linked internal User Record
    end
    
    Pramaan->>Core: Create internal session token for user
    Core-->>Adapter: Session Created
    Adapter-->>User: Redirect to dashboard (with Auth Cookie)
```

---

## 6. Astra Mudra (WebAuthn Module / `astraauth.webauthn`)

Houses FIDO2 ceremony controllers, handles registration/authentication challenges, and verifies cryptographic public keys.

### System Context
```mermaid
graph LR
    Mudra["astraauth-webauthn / astraauth.webauthn"]
    FIDO2["fido2 Library"]
    Core["astraauth-core / astraauth.core"]
    WebAuthnStore["SQL Key Credentials Store"]

    Mudra --> FIDO2
    Mudra --> Core
    Mudra --> WebAuthnStore
```

### Module Architecture
*   `store.py` & `sql_store.py`: Declares structures and handles relational databases mapping for registered WebAuthn credentials (public keys, signatures, usage counters).
*   `models.py`: Schemas for FIDO2 ceremony states, challenge requests, and registration responses.
*   `services.py`: Implements key registration verification and assertion ceremony validations.

### Core Workflow: WebAuthn Assertion/Login Ceremony
```mermaid
sequenceDiagram
    actor User as User Agent
    participant Adapter as Adapters
    participant WebAuthn as astraauth.webauthn
    participant DB as SQL Credential Store
    participant Core as astraauth.core

    User->>Adapter: Request Login Options (Username)
    Adapter->>Mudra: Build Assertion Options
    Mudra->>DB: Query registered public keys for Username
    DB-->>Mudra: Keys list
    Mudra->>Mudra: Generate challenge parameters (via fido2)
    Mudra-->>User: Return options + challenge (HTTP 200)
    
    User->>User: Call navigator.credentials.get() (User signs challenge)
    User->>Adapter: Submit signed challenge assertion
    Adapter->>Mudra: Verify Assertion
    Mudra->>DB: Fetch public key for signing key ID
    DB-->>Mudra: Public key
    Mudra->>Mudra: Verify cryptographically (Signature, Origin, and RP ID)
    
    alt Cryptographic Signature Valid
        Mudra->>Core: Upgrade Session authentication state to MFA-Approved
        Core-->>Adapter: Authentication Complete
        Adapter-->>User: Return HTTP 200 (Success)
    else Signature Invalid
        Mudra-->>Adapter: Raise VerificationError (Authentication Fails)
    end
```

---

## 7. Astra Tantra (Plugins Hub / `astraauth-plugins`)

The separate workspace package housing standard builtin plugins and serving as the hub/registry for community extensions.

### System Context
```mermaid
graph LR
    Hub["astraauth-plugins (Hub)"]
    CorePlugins["astraauth.plugins (Engine)"]
    Builtins["Builtin Plugins (Geo/Risk)"]

    Hub --> CorePlugins
    Hub --> Builtins
```

### Module Architecture
*   `builtin_plugins.py`: Houses the standard `GeoSignalPlugin` and `RiskSignalPlugin` parameters.
*   `__init__.py`: Serves as the plugin hub registration gateway, exposing built-in plugins and re-exporting key execution contracts from `astraauth.plugins` for backward compatibility.
*   `examples.py`: Minimal references representing how third-party plugins configure hooks.

---

## 8. Astra Dwaar (Operator CLI / `astraauth-cli`)

The operator interface providing text prompt wizards, textual TUIs, database setup checks, and key backup controllers.

### System Context
```mermaid
graph TD
    CLI["astraauth-cli"]
    Service["astraauth.service"]
    Console["Operator Terminal console"]
    Backup["Encrypted State Files"]

    CLI --> Service
    CLI --> Console
    CLI --> Backup
```

---

## 9. Astra Netra (Admin UI Console / `astraauth-admin-ui`)

A FastAPI-powered web-dashboard utilizing HTMX to allow real-time configurations, audits, and key updates without client JavaScript bundles.

### System Context
```mermaid
graph TD
    AdminUI["astraauth-admin-ui"]
    Service["astraauth.service"]
    HTMX["HTMX AJAX Web Clients"]
    Templates["HTMY Templates & Static Assets"]

    AdminUI --> Service
    AdminUI --> HTMX
    AdminUI --> Templates
```

---

## 10. Astra Niyam (ReBAC Policy Engine / `astraauth-policy`)

A Zanzibar-inspired relationship-based access control engine providing schema parsing and check evaluation.

### System Context
```mermaid
graph TD
    Policy["astraauth-policy"]
    Store["RelationTupleStore (In-memory/Relational)"]
    Parser["SchemaParser (DSL compiler)"]
    Engine["CheckEngine (Transitive solver)"]

    Policy --> Store
    Policy --> Parser
    Policy --> Engine
```

### Module Architecture
*   `parser.py`: Schema compiler parsing KeyNetra-style entity relationship DSL declarations.
*   `engine.py`: Transitive check query solver executing graph traversal algorithm calls.
*   `store.py`: Models and query interfaces for relation fact assertions.

---

## 11. Astra Mandal (Multi-Tenancy / `astraauth-tenancy`)

Provides request context tenant context bindings and ASGI/Flask routing middleware.

### System Context
```mermaid
graph TD
    Tenancy["astraauth-tenancy"]
    Context["ContextVar variables"]
    ASGI["ASGITenancyMiddleware"]
    Flask["Flask context hooks"]

    Tenancy --> Context
    Tenancy --> ASGI
    Tenancy --> Flask
```

### Module Architecture
*   `models.py`: Tracks workspace boundaries and database connection strings.
*   `middleware.py`: Integrates `ASGITenancyMiddleware` and Flask hooks to dynamically intercept and set context variables.

```
