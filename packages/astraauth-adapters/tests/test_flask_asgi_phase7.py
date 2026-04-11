# ruff: noqa: I001
from __future__ import annotations

from astraauth_service import build_inmemory_service
import pytest


def test_create_asgi_app_exposes_runtime_routes() -> None:
    starlette = pytest.importorskip("starlette.testclient")

    from astraauth_adapters.asgi.wiring import create_asgi_app

    service = build_inmemory_service(default_plugins_enabled=False)
    client = starlette.TestClient(create_asgi_app(adapter=service.adapter, issuer="https://auth.example.com"))

    jwks = client.get("/.well-known/jwks.json")
    config = client.get("/.well-known/openid-configuration")

    assert jwks.status_code == 200
    assert "keys" in jwks.json()
    assert config.status_code == 200
    assert config.json()["issuer"] == "https://auth.example.com"


def test_mount_oauth_flask_exposes_runtime_routes() -> None:
    flask = pytest.importorskip("flask")

    from astraauth_adapters.flask.wiring import mount_oauth

    service = build_inmemory_service(default_plugins_enabled=False)
    app = flask.Flask(__name__)
    mount_oauth(app, service.adapter, issuer="https://auth.example.com")
    client = app.test_client()

    jwks = client.get("/.well-known/jwks.json")
    config = client.get("/.well-known/openid-configuration")

    assert jwks.status_code == 200
    assert "keys" in jwks.get_json()
    assert config.status_code == 200
    assert config.get_json()["issuer"] == "https://auth.example.com"
