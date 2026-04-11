# Astra Setu (`astraauth-adapters`)

Framework wiring for Astra's normalized HTTP adapter.

## Best For

- mounting Astra into an existing Python web framework
- keeping auth behavior consistent across multiple frameworks
- exposing plugin endpoints through the same adapter contract

## Includes

- generic ASGI adapter
- Django adapter
- Flask adapter
- FastAPI, Litestar, and Robyn wiring
- plugin endpoint materialization helpers

## Typical Use

```python
from astraauth_adapters import create_asgi_app
from astraauth_service import build_inmemory_service

service = build_inmemory_service(default_plugins_enabled=False)
app = create_asgi_app(adapter=service.adapter, issuer='https://auth.local')
```

## Public API Areas

- generic ASGI app creation
- FastAPI mount helpers
- Flask mount helpers
- Django URL pattern helpers
- plugin endpoint materialization helpers

## Flask Example

```python
from flask import Flask
from astraauth_adapters import mount_oauth_flask
from astraauth_service import build_inmemory_service

service = build_inmemory_service(default_plugins_enabled=False)
app = Flask(__name__)
mount_oauth_flask(app, service.adapter, issuer='https://auth.local')
```

## Django Example

```python
from astraauth_adapters import build_django_urlpatterns
from astraauth_service import build_inmemory_service

service = build_inmemory_service(default_plugins_enabled=False)
urlpatterns = build_django_urlpatterns(
    adapter=service.adapter,
    issuer="https://auth.local",
)
```

## Install Matrix

- generic ASGI: `uv sync --extra asgi`
- Flask: `uv sync --extra flask`
- Django: `uv sync --extra django`
- all adapter extras: `uv sync --extra all`

## Tests

```bash
uv run pytest -q packages/astraauth-adapters/tests
```
