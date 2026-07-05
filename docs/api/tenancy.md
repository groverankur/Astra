# Tenancy API Reference

This page documents the programmatic API for the **Astra Mandal** multi-tenancy context isolation system.

## Tenant Workspace Models

::: astraauth_tenancy.models.TenantWorkspace
    options:
      show_root_heading: true

## Tenancy Middleware & Context Helpers

::: astraauth_tenancy.middleware.ASGITenancyMiddleware
    options:
      show_root_heading: true

::: astraauth_tenancy.middleware.mount_flask_tenancy_routing
    options:
      show_root_heading: true

::: astraauth_tenancy.middleware.get_current_tenant
    options:
      show_root_heading: true

::: astraauth_tenancy.middleware.set_current_tenant
    options:
      show_root_heading: true

::: astraauth_tenancy.middleware.reset_current_tenant
    options:
      show_root_heading: true

