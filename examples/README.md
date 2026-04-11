# Examples

This folder contains runnable examples that map to the current package surfaces and feature set.

## Quick map

- `01_bootstrap_runtime.py`
  - local runtime bootstrap
- `02_password_email_otp_step_up.py`
  - password + MFA step-up
- `03_oidc_federation.py`
  - enterprise OIDC federation
- `04_hybrid_authorization.py`
  - hybrid authorization behavior
- `05_asgi_app.py`
  - generic ASGI integration
- `06_flask_app.py`
  - Flask integration
- `07_config_reload.py`
  - config reload and runtime rebuild
- `08_flask_deployment.py`
  - Flask deployment shape
- `09_django_deployment.py`
  - Django deployment shape
- `10_admin_web_ui.py`
  - browser admin UI showcase

## Best starting order

1. `01_bootstrap_runtime.py`
2. `02_password_email_otp_step_up.py`
3. `03_oidc_federation.py`
4. `10_admin_web_ui.py`

For the MKDocs site, start with [docs/index.md](../docs/index.md) and the bootstrap walkthrough at [docs/examples/bootstrap-runtime.md](../docs/examples/bootstrap-runtime.md).
