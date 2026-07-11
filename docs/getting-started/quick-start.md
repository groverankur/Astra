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

## 6. Run The Unified Security Dashboard
Astra contains a modern Obsidian-themed dashboard showcasing session audits, ReBAC live solver playground, and Multi-Factor settings:

```bash
uv run python examples/astra_demo.py
```
Open [http://127.0.0.1:8000](http://127.0.0.1:8000) in your browser.

## 7. Explore The Web Framework Sample Apps
We provide sample web applications demonstrating login/logout, session management, middleware wiring, and step-up MFA challenge prompts:

- FastAPI: `examples/fastapi_app.py`
- Django: `examples/django_app.py`
- Flask: `examples/flask_app.py`
- Litestar: `examples/litestar_app.py`
- Robyn: `examples/robyn_app.py`

See [Examples](../examples/index.md) for more details.

## What This Quick Start Does Not Claim

- It does not claim FAPI certification.
- It does not enable SAML or LDAP/AD.
