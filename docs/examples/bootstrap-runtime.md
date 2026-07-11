# Bootstrap Runtime Example

Astra is configured locally via a centralized runtime service. The main entry point to view this bootstrap process is **[Astra Demo](https://github.com/groverankur/Astra/tree/main/examples/astra_demo.py)** (`examples/astra_demo.py`).

## What It Shows

- **Runtime Home Initialisation**: Setting up keys, database backends (SQLite), and tenant configurations in the local environment.
- **Relational Persistence**: Initialising database schemas and seeding users, roles, and ReBAC relation tuples.
- **Policy Store Seeding**: Registering permissions, roles (e.g. `admin`, `user`), and attribute-based access control (ABAC) rules.
- **MFA and Federation Configuration**: Enrolling mock WebAuthn passkeys and configuring external OIDC providers.

## Run It

To boot the unified security dashboard and inspect the bootstrapped service:

```bash
uv run python examples/astra_demo.py
```

Then open [http://127.0.0.1:8000](http://127.0.0.1:8000) in your browser.

## Other Integrated Examples

Once bootstrapped, you can run and explore specific web framework adapter integrations:

- **FastAPI**: `examples/fastapi_app.py` (Port 8000)
- **Django**: `examples/django_app.py` (Port 8080)
- **Flask**: `examples/flask_app.py` (Port 5000)
- **Litestar**: `examples/litestar_app.py` (Port 8001)
- **Robyn**: `examples/robyn_app.py` (Port 8002)

The full examples index is [Examples](index.md).
