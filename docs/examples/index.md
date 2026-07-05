# Examples

The repo examples are local demos and deployment-shaped references. They are designed to be safe to inspect and smoke-test without external network dependencies unless the file says otherwise.

See the full index in the repo root at `examples/README.md`.

## Supported Adapter Coverage

| Adapter | Example | Behavior |
| --- | --- | --- |
| Generic ASGI | `examples/05_asgi_app.py` | constructs an ASGI app with local origin policy |
| Flask | `examples/06_flask_app.py` | exposes `build_app()` for a minimal Flask mount |
| Flask deployment | `examples/08_flask_deployment.py` | exposes `build_app()` and creates a local runtime home when run |
| Django | `examples/09_django_deployment.py` | exposes `build_urlpatterns()` for project URLConf inclusion |
| FastAPI | `examples/11_fastapi_e2e_app.py` | exposes `build_app()` for an integrated OAuth/MFA/OIDC/WebAuthn/plugin demo |
| Litestar | `examples/12_litestar_app.py` | exposes `build_app()` and only serves when `ASTRAAUTH_EXAMPLE_SERVE=1` |
| Robyn | `examples/13_robyn_app.py` | exposes `build_app()` and only serves when `ASTRAAUTH_EXAMPLE_SERVE=1` |

All adapter examples show or use `AdapterOriginPolicy` so browser-facing state-changing requests are not implicitly trusted across origins. Framework examples construct without binding ports by default; serving is opt-in where supported.

## Release-Critical Safety Examples

- Encrypted bootstrap export: `examples/14_encrypted_bootstrap_export.py`
- Plugin trust policy: `examples/15_plugin_trust_policy.py`
- WebAuthn production verifier wiring: `examples/16_webauthn_production_verifier.py`

Demo credentials and secrets in examples are local-only placeholders. Replace them before using the pattern outside a disposable local runtime.
