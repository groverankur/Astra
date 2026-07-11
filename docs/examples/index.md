# Examples

The repo examples are local demos and deployment-shaped references. They are designed to be safe to inspect and smoke-test without external network dependencies unless the file says otherwise.

See the full index in the repo root at `examples/README.md`.

| Adapter | Example | Behavior |
| --- | --- | --- |
| **Astra Demo** | `examples/astra_demo.py` | Unified Security Dashboard Demo SPA showing Zanzibar ReBAC, audits, and MFA. |
| **FastAPI** | `examples/fastapi_app.py` | Exposes end-to-end FastAPI setup with OAuth/MFA/OIDC/WebAuthn/plugin demo. |
| **Django** | `examples/django_app.py` | Exposes `build_urlpatterns()` and views for project URLConf inclusion. |
| **Flask** | `examples/flask_app.py` | Minimal and production-shaped Flask configuration mount. |
| **Litestar** | `examples/litestar_app.py` | End-to-end Litestar mount with cookie session state management. |
| **Robyn** | `examples/robyn_app.py` | Robyn (Rust-based web server) app showing session checking and step-up MFA. |

All adapter examples show or use `AdapterOriginPolicy` so browser-facing state-changing requests are not implicitly trusted across origins.
Demo credentials and secrets in examples are local-only placeholders. Replace them before using the pattern outside a disposable local runtime.
