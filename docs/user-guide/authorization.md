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

In addition to the core hybrid authorization model, Astra provides advanced components to handle enterprise relationship checking and multi-tenant segmentation:

| Component Name | Technical Module | Description |
| :--- | :--- | :--- |
| **Astra Niyam** | `astraauth-policy` | Zanzibar-style relationship-based access control (ReBAC) system to evaluate transitive permission paths. |
| **Astra Mandal** | `astraauth-tenancy` | Strict tenant policy isolation boundaries, workspace thresholds, and context bindings. |
| **Astra Netra** | `astraauth-admin-ui` | Visual schema playground, relationship compilers, and live checkers on the console. |

> [!TIP]
> For implementation specifics, check the dedicated guides:
> *   📖 **[ReBAC Access Policies Guide](rebac-policies.md)** — Zanzibar DSL declarations, CheckEngine, and graph traversal.
> *   📖 **[Multi-Tenancy Isolation Guide](multi-tenancy.md)** — ASGI tenancy middleware, workspace contexts, and tenant databases.


---

## 🔌 Dependency Injection (DI) Patterns

Instead of referencing global services or policy engines directly inside view handlers, we recommend utilizing framework-level Dependency Injection (DI) to inject `AstraAuthService` or the `PermissionEngine` cleanly.

### 1. Robyn Dependency Injection
Robyn supports registering dependencies at the application level via `app.inject()`. Route handlers can then declare these dependencies as arguments:

```python
from robyn import Robyn, Request
from astraauth.service import AstraAuthService

app = Robyn(__file__)
service = build_inmemory_service()

# Register the service dependency
app.inject(astra_service=service)

@app.get("/documents/:doc_id")
async def get_document(request: Request, astra_service: AstraAuthService):
    session = get_session_from_request(request)
    engine = astra_service.adapter._authorization_engine
    
    if not engine.has_permission(session.subject_id, session.tenant_id, "documents.read"):
        return Response(status_code=403, description="Forbidden")
        
    return Response(status_code=200, description="Document content")
```

### 2. Litestar Dependency Injection
Litestar manages dependencies via the `Provide` dependency graph, allowing dependencies to be declared at the controller, router, or application scope:

```python
from litestar import Litestar, Request, get
from litestar.di import Provide
from astraauth.service import AstraAuthService

def get_auth_service() -> AstraAuthService:
    return build_inmemory_service()

@get("/documents/{doc_id:str}")
async def get_document(request: Request, astra_service: AstraAuthService) -> dict:
    session = get_session_from_request(request)
    engine = astra_service.adapter._authorization_engine
    
    if not engine.has_permission(session.subject_id, session.tenant_id, "documents.read"):
        raise HTTPException(status_code=403, detail="Forbidden")
        
    return {"status": "success"}

# Bind the dependency provider to the application
app = Litestar(
    route_handlers=[get_document],
    dependencies={"astra_service": Provide(get_auth_service)}
)
```

### 3. FastAPI Dependency Injection
FastAPI offers a native, route-level dependency injection system via `Depends()`. You can write dependency functions that return the centralized `AstraAuthService` or the `PermissionEngine` directly:

```python
from fastapi import FastAPI, Depends, Request, HTTPException
from astraauth.service import AstraAuthService

app = FastAPI()

# Singleton or factory function for DI
def get_astra_service() -> AstraAuthService:
    # Resolves the bootstrapped service instance
    return global_service_instance

@app.get("/documents/{doc_id}")
async def get_document(
    doc_id: str,
    request: Request,
    astra_service: AstraAuthService = Depends(get_astra_service)
):
    session = get_session_from_request(request)
    engine = astra_service.adapter._authorization_engine
    
    if not engine.has_permission(session.subject_id, session.tenant_id, "documents.read"):
        raise HTTPException(status_code=403, detail="Forbidden")
        
    return {"status": "success"}
```

### 4. Flask Context Dependency Binding
Since Flask views are standard functions and do not support parameter-based injection natively, the standard practice is to bind the service instance to Flask's `current_app` (during bootstrap) or write a route decorator/request hook that assigns it to the context-local `flask.g` object:

```python
from flask import Flask, g, request, jsonify
from astraauth.service import AstraAuthService

app = Flask(__name__)
service = build_inmemory_service()

# Bind singleton instance to current_app context
app.astra_service = service

@app.before_request
def setup_request_context():
    # Bind to request-scoped context-local global
    g.astra_service = app.astra_service

@app.route("/documents/<doc_id>", methods=["GET"])
def get_document(doc_id):
    # Resolve the service dependency from context local
    astra_service: AstraAuthService = g.astra_service
    session = get_session_from_request(request)
    engine = astra_service.adapter._authorization_engine
    
    if not engine.has_permission(session.subject_id, session.tenant_id, "documents.read"):
        return jsonify({"error": "Forbidden"}), 403
        
    return jsonify({"status": "success"})
```

### 5. Django Service Registry
For Django views, you can define a centralized service registry or register the service within Django's AppConfig, resolving it lazily inside class-based or functional views:

```python
# apps.py (Django App Config)
from django.apps import AppConfig
from astraauth.service import AstraAuthService

class AstraAuthConfig(AppConfig):
    name = 'my_app'
    
    def ready(self):
        # Bootstrap and keep reference to the service
        self.astra_service = build_inmemory_service()

# views.py
from django.apps import apps
from django.http import JsonResponse, HttpResponseForbidden

def get_astra_service() -> AstraAuthService:
    return apps.get_app_config('my_app').astra_service

def get_document(request, doc_id):
    astra_service = get_astra_service()
    session = get_session_from_request(request)
    engine = astra_service.adapter._authorization_engine
    
    if not engine.has_permission(session.subject_id, session.tenant_id, "documents.read"):
        return HttpResponseForbidden("Forbidden")
        
    return JsonResponse({"status": "success"})
```

### 6. Framework-Agnostic DI with Dishka
For projects that want a unified, framework-agnostic DI layer, [Dishka](https://dishka.readthedocs.io/en/stable/integrations/index.html) provides out-of-the-box integrations for FastAPI, Litestar, Flask, Django, Robyn, and more.

Define a Dishka Provider container:

```python
from dishka import Provider, Scope, provide, make_container
from astraauth.service import AstraAuthService

class AstraProvider(Provider):
    @provide(scope=Scope.APP)
    def get_auth_service(self) -> AstraAuthService:
        return build_inmemory_service()

# Create the DI container
container = make_container(AstraProvider())
```

Then integrate it into your chosen web framework handler (e.g., using Dishka's decorator wrapper or framework context binding):

```python
from dishka.integrations.fastapi import FromDishka, inject

@app.get("/documents/{doc_id}")
@inject
async def get_document(
    doc_id: str, 
    astra_service: FromDishka[AstraAuthService]
):
    # Use the injected astra_service here
    ...
```


