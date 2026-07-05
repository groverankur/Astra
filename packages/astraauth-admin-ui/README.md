# Astra Netra (`astraauth-admin-ui`)

Browser-based admin UI for Astra built with FastAPI, Jinja templates, Basecoat local assets, Jinja macros, and htmx partial updates.

## Best For

- operator-facing demos and runtime inspection
- browser-based config/bootstrap/key workflows
- showcasing Astra features without building a separate frontend application

## What it provides

- authenticated operator login backed by Astra admin credentials
- setup mode for first-run config and first admin creation when no bootstrap admin exists yet
- CSRF-protected admin actions
- encrypted admin action audit trail
- dashboard-style operator workspace with a persistent sidebar
- runtime dashboard for health, persistence, bootstrap state, JWKS, and observability
- security diagnostics for runtime throttling state, admin UI throttle state, and recent plugin runtime audit records
- operator-friendly summary cards and drill-down panels instead of raw JSON-only views
- readable light and dark operator themes with predictable wrapping for long IDs, paths, DSNs, and audit details
- compact mobile layouts for runtime inspection and sensitive admin actions
- default security headers and no-store caching on dynamic admin responses
- shared SQLite-backed throttling for repeated login failures and sensitive operator actions
- interactive config initialization
- bootstrap admin creation
- runtime key rotation
- OIDC audit browsing
- recent admin action history
- packaged local CSS/JS assets instead of CDN styling
- partial HTML updates for key actions and audit panels without full page refreshes

## Run it

```bash
python -m astraauth_admin_ui serve --home .astraauth --host 127.0.0.1 --port 8088
```

Then open `http://127.0.0.1:8088/`.

## Operator flow

1. On a brand-new runtime home, the UI starts in setup mode.
2. Generate a short-lived bootstrap setup token with the CLI.
3. Initialize config and create the first bootstrap admin using that token.
4. Sign in with that admin account to unlock the operator dashboard.
5. Use the dashboard for runtime inspection, key rotation, and audit review.

## Public API

```python
from astraauth_admin_ui import create_admin_app

app = create_admin_app()
```

## Implementation notes

- the UI now renders through Jinja templates rather than a single inline HTML string
- repeated layout and form patterns are expressed through Jinja macros
- key workflows use htmx partial endpoints so panels refresh in place
- Basecoat assets are vendored locally under `astraauth_admin_ui/static/vendor/basecoat`
- htmx is vendored locally under `astraauth_admin_ui/static/vendor/htmx`
- the package serves its own static CSS/JS through FastAPI `StaticFiles`
- Bun is used only as the asset-vendoring path for Basecoat and htmx; runtime rendering stays entirely Python/FastAPI/Jinja
- throttling state is stored under the runtime home so multiple admin UI workers share the same counters
