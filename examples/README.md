# AstraAuth Sample Apps & Examples

These polished, end-to-end examples showcase how to integrate AstraAuth authentication, authorization, and operator tools within modern hypermedia interfaces and backend Python web frameworks.

---

## 1. Unified Security Dashboard Demo

* **[Astra Demo](https://github.com/groverankur/Astra/tree/main/examples/astra_demo.py)** (FastAPI, Port 8000)
  - An Obsidian-themed modern SPA showcasing:
    - **Session Auditing**: Active user session listings and remote revocation.
    - **Zanzibar ReBAC Evaluator**: Schema compiling and live policy evaluations.
    - **Multi-Factor Settings**: Enrolling/managing TOTP factors.
    - **User Profile Cards**: Rich aesthetic layout of operational identity scopes.

Run:
```bash
uv run python examples/astra_demo.py
```
Open [http://127.0.0.1:8000](http://127.0.0.1:8000) in your browser.

---

## 2. Web Framework Integration Examples

These sample apps showcase session management, login/logout routes, RBAC/ABAC middleware wiring, and step-up MFA challenge prompts.

| Framework | File | Default Port | Run Command |
|---|---|---|---|
| **FastAPI** | [fastapi_app.py](https://github.com/groverankur/Astra/tree/main/examples/fastapi_app.py) | `8000` | `uv run python examples/fastapi_app.py` |
| **Django** | [django_app.py](https://github.com/groverankur/Astra/tree/main/examples/django_app.py) | `8080` | `uv run python examples/django_app.py` |
| **Flask** | [flask_app.py](https://github.com/groverankur/Astra/tree/main/examples/flask_app.py) | `5000` | `uv run python examples/flask_app.py` |
| **Litestar** | [litestar_app.py](https://github.com/groverankur/Astra/tree/main/examples/litestar_app.py) | `8001` | `uv run python examples/litestar_app.py` |
| **Robyn** | [robyn_app.py](https://github.com/groverankur/Astra/tree/main/examples/robyn_app.py) | `8002` | `uv run python examples/robyn_app.py` |

All framework examples share these local demo credentials:
* **Administrator**: `alice` / `alice-password` (Full access to read & delete documents)
* **Standard User**: `bob` / `bob-password` (Access to read documents only)

---

## Safety & Local Deployment Rules

* **Local-Only Values**: These scripts contain dummy signing keys, OIDC client secrets, and passwords. Never reuse these defaults in production workspaces.
* **Workspaces**: When run, examples auto-configure disposable workspace environments under temporary directories in order to inspect active states safely.