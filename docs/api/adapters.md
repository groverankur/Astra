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
| Generic ASGI | `examples/05_asgi_app.py` | constructs an ASGI app with `AdapterOriginPolicy` |
| FastAPI | `examples/11_fastapi_e2e_app.py` | integrated reference app; `build_app()` returns the app |
| Flask | `examples/06_flask_app.py` | minimal `build_app()` example |
| Flask deployment | `examples/08_flask_deployment.py` | deployment-shaped `build_app()` example |
| Django | `examples/09_django_deployment.py` | `build_urlpatterns()` for URLConf inclusion |
| Litestar | `examples/12_litestar_app.py` | `build_app()`; server start is opt-in with `ASTRAAUTH_EXAMPLE_SERVE=1` |
| Robyn | `examples/13_robyn_app.py` | `build_app()`; server start is opt-in with `ASTRAAUTH_EXAMPLE_SERVE=1` |

Examples are designed to import and construct without binding ports during tests. Optional framework examples print installation guidance and exit cleanly when the extra is not installed.
