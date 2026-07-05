# Multi-Tenancy Isolation (Astra Mandal)

Astra provides multi-tenancy support to partition operator spaces and database persistence routes.

## Tenant Workspace Modeling

Each tenant is modeled with distinct limits and database connection configurations:

```python
from astraauth_tenancy import TenantWorkspace

workspace = TenantWorkspace(
    tenant_id="tenant-123",
    name="Enterprise Corp",
    database_url="postgresql://user:password@localhost/tenant_123",
    max_users=5000,
    max_relation_tuples=20000,
)
```

## Context Bindings

Astra uses thread-safe and async-safe Python `contextvars` to bind request context to a specific tenant ID:

```python
from astraauth_tenancy import set_current_tenant, get_current_tenant, reset_current_tenant

# Bind
token = set_current_tenant("tenant-123")

# Get active tenant ID in any nested service or model layer
tenant_id = get_current_tenant()  # returns "tenant-123"

# Reset
reset_current_tenant(token)
```

## ASGI Tenancy Middleware

You can use the built-in ASGI middleware to intercept incoming requests and bind the context using headers (e.g. `X-Tenant-ID`):

```python
from astraauth_tenancy import ASGITenancyMiddleware

# Wrap your ASGI or FastAPI application
app = ASGITenancyMiddleware(app, header_name="X-Tenant-ID")
```

## Flask Tenancy Mount

For Flask applications, you can mount before_request/after_request context handlers:

```python
from astraauth_tenancy import mount_flask_tenancy_routing

app = Flask(__name__)
mount_flask_tenancy_routing(app, header_name="X-Tenant-ID")
```

## Graphical Tenancy Console

Astra Netra (**Astra browser admin UI**) provides a built-in Tenants Management Console:
- **Visual Listing**: Displays active tenant workspaces, their isolation limits, and database connections.
- **Register New Tenants**: An interactive form to define tenant metadata, database connection strings, maximum user counts, and maximum relation tuple limits.
- **Dynamic Operations**: Add and delete tenant workspaces on-the-fly.

Access it by running `uv run astra admin-ui` and navigating to the **Tenants** tab in the sidebar.
