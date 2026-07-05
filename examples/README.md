# AstraAuth Examples

These examples are local demos and deployment-shaped references for the packages in this repo. Files that include credentials, API keys, OIDC client secrets, or bootstrap admins use local-only demo values. Replace them before using the pattern in a shared or production environment.

## Runtime and Feature Examples

| Example | Packages | Shows |
| --- | --- | --- |
| `01_bootstrap_runtime.py` | `astraauth-core`, `astraauth-service` | local runtime home, config, health report, OIDC discovery |
| `02_password_email_otp_step_up.py` | `astraauth-core`, `astraauth-service` | password grant plus email OTP step-up |
| `03_oidc_federation.py` | `astraauth-idp`, `astraauth-service` | OIDC provider configuration, mapping, and audit |
| `04_hybrid_authorization.py` | `astraauth-core` | role/permission authorization model |
| `07_config_reload.py` | `astraauth-core`, `astraauth-service` | config reload from a runtime home |
| `14_encrypted_bootstrap_export.py` | `astraauth-service` | default encrypted bootstrap export without unsafe plaintext |
| `15_plugin_trust_policy.py` | `astraauth-plugins`, `astraauth-service` | plugin allowlist, manifest metadata, tenant enablement |
| `16_webauthn_production_verifier.py` | `astraauth-webauthn`, `astraauth-service` | production-safe default WebAuthn verifier wiring |
| `17_event_bus_zeromq.py` | `astraauth-core` | ZeroMQ pub/sub event bus with concurrent subscriber poller |
| `18_event_bus_inmemory_redis.py` | `astraauth-core` | InMemory callback event routing and Redis PubSub config |
| `19_rebac_policy_tenancy.py` | `astraauth-policy`, `astraauth-tenancy` | ReBAC Zanzibar-style schema parsing, solvers, and tenant contexts |

## Adapter Examples

Every supported adapter has an example path. Framework examples construct apps by default and do not bind network ports unless the file explicitly says how to serve it.

| Adapter | Example | Shape | Notes |
| --- | --- | --- | --- |
| Generic ASGI | `05_asgi_app.py` | minimal construction | local app with `AdapterOriginPolicy` |
| Flask | `06_flask_app.py` | minimal construction | exposes `build_app()` and mounts OAuth routes |
| Flask | `08_flask_deployment.py` | deployment-shaped construction | creates runtime home when run, exposes `build_app()` for WSGI servers |
| Django | `09_django_deployment.py` | deployment-shaped URLConf | exposes `build_urlpatterns()` with origin policy |
| FastAPI | `11_fastapi_e2e_app.py` | integrated feature app | exposes `build_app()` and covers OAuth, MFA, WebAuthn, OIDC, and plugins |
| Litestar | `12_litestar_app.py` | minimal construction | exposes `build_app()`; optional extra required |
| Robyn | `13_robyn_app.py` | minimal construction | exposes `build_app()`; optional extra required |

## Admin UI

`10_admin_web_ui.py` starts Astra Netra on `127.0.0.1` with a local `.astraauth` home. It is intended for local operator demos and setup-flow inspection, not direct internet exposure.

## Running

Run examples from the repo root so `_support.py` can create disposable workspaces where needed:

```bash
python examples/01_bootstrap_runtime.py
python examples/14_encrypted_bootstrap_export.py
```

Framework examples that depend on optional packages print an install hint and exit cleanly when the extra is not installed. Examples that can start a server use opt-in serving so CI and docs smoke tests never bind ports by default:

```bash
ASTRAAUTH_EXAMPLE_SERVE=1 python examples/11_fastapi_e2e_app.py
ASTRAAUTH_EXAMPLE_SERVE=1 python examples/12_litestar_app.py
ASTRAAUTH_EXAMPLE_SERVE=1 python examples/13_robyn_app.py
```

## Safety Rules

- Do not reuse demo passwords, API keys, OIDC client secrets, or bootstrap admins.
- Keep default bootstrap exports encrypted. Use unsafe plaintext exports only for throwaway local demonstrations.
- Configure `AdapterOriginPolicy` for browser-facing adapters before accepting unsafe cross-origin requests.
- Require signed plugin manifests and a configured trust root for production plugins.
- Provide full WebAuthn ceremony responses, expected origin, and relying-party ID when finishing registration or authentication.
