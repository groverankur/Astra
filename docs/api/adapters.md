# Adapters API Reference

AstraAuth supports six release-facing adapters:

- generic ASGI
- FastAPI
- Flask
- Django
- Robyn
- Litestar

All runtime adapter mounts accept `AdapterOriginPolicy` where the framework API
can pass options. The policy rejects unsafe cross-origin state-changing requests
from origins outside the allowlist, emits CORS headers for allowed origins, and
supports a separate callback-origin allowlist for OIDC callback routes.

::: astraauth.adapters
    options:
      show_root_heading: true
      show_root_toc_entry: false
      inherited_members: true


## Working Examples

Each supported adapter has a smoke-testable example:

| Adapter | Example | Notes |
| --- | --- | --- |
| **Astra Demo** | `examples/astra_demo.py` | Unified Security Dashboard Demo showing ReBAC, session audits, and MFA. |
| **FastAPI** | `examples/fastapi_app.py` | Polished FastAPI E2E application; `build_app()` returns the app. |
| **Django** | `examples/django_app.py` | Django adapter using `build_urlpatterns()` for URLConf inclusion. |
| **Flask** | `examples/flask_app.py` | Minimal and production-shaped Flask configuration mount. |
| **Litestar** | `examples/litestar_app.py` | `build_app()`; server start is opt-in with `ASTRAAUTH_EXAMPLE_SERVE=1`. |
| **Robyn** | `examples/robyn_app.py` | `build_app()`; server start is opt-in with `ASTRAAUTH_EXAMPLE_SERVE=1`. |

Examples are designed to import and construct without binding ports during tests. Optional framework examples print installation guidance and exit cleanly when the extra is not installed.
