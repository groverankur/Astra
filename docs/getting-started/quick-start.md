# Quick Start

This quick start uses the current integrated runtime path instead of the older prototype APIs.

## 1. Create a Runtime Home

```bash
uv run astra config-init --home .astraauth --environment dev --persistence-backend sqlite
```

## 2. Validate and Create Schema

```bash
uv run astra validate-config --home .astraauth
uv run astra schema-ensure --home .astraauth --json
```

## 3. Create a Bootstrap Admin

```bash
uv run astra init-admin --home .astraauth --tenant-id tenant-1 --username admin --password change-me
```

If you plan to use the browser admin UI for first-run setup instead, generate a setup token instead of creating the admin directly:

```bash
uv run astra bootstrap-token-create --home .astraauth --label local-setup
```

## 4. Inspect Runtime Health

```bash
uv run astra health --home .astraauth --json
uv run astra runtime-inventory --home .astraauth --json
```

## 5. Try The Operator Surfaces

Interactive CLI setup wizard:

```bash
uv run astra wizard --home .astraauth
```

Browser admin UI web server (default port 8088):

```bash
uv run astra admin-ui --home .astraauth --port 8088
```

Alternatively, run the terminal-based admin dashboard:

```bash
uv run astra admin-ui --home .astraauth --tui
```

## 6. Run The Bootstrap Example

```bash
uv run python examples/01_bootstrap_runtime.py
```

## 7. Explore The Feature Examples

- `examples/02_password_email_otp_step_up.py`
- `examples/03_oidc_federation.py`
- `examples/04_hybrid_authorization.py`
- `examples/11_fastapi_e2e_app.py`
  Developer reference app only. It uses demo credentials, mock OIDC behavior, and local-friendly defaults, so it should not be deployed unchanged.
- `examples/14_encrypted_bootstrap_export.py`

See [Examples](../examples/index.md) for the supported ASGI, FastAPI, Flask, Django, Litestar, and Robyn adapter examples.

## What This Quick Start Does Not Claim

- It does not claim FAPI certification.
- It does not enable SAML or LDAP/AD.
