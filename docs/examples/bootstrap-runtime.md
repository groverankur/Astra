# Bootstrap Runtime Example

The current bootstrap example is `examples/01_bootstrap_runtime.py`.

## What It Shows

- creating a runtime home
- initializing config
- preparing schema
- creating a bootstrap admin
- checking runtime health

## Run It

```bash
uv run python examples/01_bootstrap_runtime.py
```

## Related Examples

- `examples/02_password_email_otp_step_up.py`
- `examples/03_oidc_federation.py`
- `examples/11_fastapi_e2e_app.py`
  This is a developer reference application that intentionally uses demo credentials and mock federation behavior.
- `examples/10_admin_web_ui.py`
  This shows the browser admin UI flow and complements the packaged `astraauth-admin-ui` surface.
- `examples/12_litestar_app.py`
- `examples/13_robyn_app.py`
- `examples/14_encrypted_bootstrap_export.py`
- `examples/15_plugin_trust_policy.py`
- `examples/16_webauthn_production_verifier.py`

The full examples index is [Examples](index.md).
