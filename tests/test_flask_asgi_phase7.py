from __future__ import annotations

import inspect

import pytest

from astraauth.adapters.origin import AdapterOriginPolicy
from astraauth.service import build_inmemory_service


def test_create_asgi_app_exposes_runtime_routes() -> None:
    starlette = pytest.importorskip("starlette.testclient")

    from astraauth.adapters.asgi.wiring import create_asgi_app

    service = build_inmemory_service(default_plugins_enabled=False)
    client = starlette.TestClient(
        create_asgi_app(adapter=service.adapter, issuer="https://auth.example.com")
    )

    jwks = client.get("/.well-known/jwks.json")
    config = client.get("/.well-known/openid-configuration")

    assert jwks.status_code == 200
    assert "keys" in jwks.json()
    assert jwks.headers["x-frame-options"] == "DENY"
    assert "cache-control" not in {key.lower() for key in jwks.headers.keys()}
    assert config.status_code == 200
    assert config.json()["issuer"] == "https://auth.example.com"
    assert config.headers["x-content-type-options"] == "nosniff"
    assert "cache-control" not in {key.lower() for key in config.headers.keys()}


def test_asgi_origin_policy_rejects_disallowed_origin() -> None:
    starlette = pytest.importorskip("starlette.testclient")

    from astraauth.adapters.asgi.wiring import create_asgi_app

    service = build_inmemory_service(default_plugins_enabled=False)
    client = starlette.TestClient(
        create_asgi_app(
            adapter=service.adapter,
            origin_policy=AdapterOriginPolicy(
                allowed_origins=frozenset({"https://app.example.com"})
            ),
        )
    )

    response = client.post("/token", headers={"Origin": "https://evil.example.com"})

    assert response.status_code == 403
    assert response.json()["error"] == "origin_not_allowed"


def test_mount_oauth_flask_exposes_runtime_routes() -> None:
    flask = pytest.importorskip("flask")

    from astraauth.adapters.flask.wiring import mount_oauth

    service = build_inmemory_service(default_plugins_enabled=False)
    app = flask.Flask(__name__)
    mount_oauth(app, service.adapter, issuer="https://auth.example.com")
    client = app.test_client()

    jwks = client.get("/.well-known/jwks.json")
    config = client.get("/.well-known/openid-configuration")

    assert jwks.status_code == 200
    assert "keys" in jwks.get_json()
    assert jwks.headers["x-frame-options"] == "DENY"
    assert "Cache-Control" not in jwks.headers
    assert config.status_code == 200
    assert config.get_json()["issuer"] == "https://auth.example.com"
    assert config.headers["X-Content-Type-Options"] == "nosniff"
    assert "Cache-Control" not in config.headers


def test_flask_origin_policy_allows_preflight() -> None:
    flask = pytest.importorskip("flask")

    from astraauth.adapters.flask.wiring import mount_oauth

    service = build_inmemory_service(default_plugins_enabled=False)
    app = flask.Flask(__name__)
    mount_oauth(
        app,
        service.adapter,
        origin_policy=AdapterOriginPolicy(allowed_origins=frozenset({"https://app.example.com"})),
    )
    client = app.test_client()

    response = client.options(
        "/token",
        headers={
            "Origin": "https://app.example.com",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert response.status_code == 204
    assert response.headers["Access-Control-Allow-Origin"] == "https://app.example.com"


def test_litestar_mount_accepts_origin_policy() -> None:
    pytest.importorskip("litestar")

    from astraauth.adapters.litestar.wiring import mount_oauth

    assert "origin_policy" in inspect.signature(mount_oauth).parameters


def test_robyn_mount_accepts_origin_policy() -> None:
    pytest.importorskip("robyn")

    from astraauth.adapters.robyn.wiring import mount_oauth

    assert "origin_policy" in inspect.signature(mount_oauth).parameters
