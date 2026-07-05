from __future__ import annotations

from pathlib import Path
from typing import Any

from astraauth.adapters import AdapterOriginPolicy
from astraauth.core.config import AuthConfig
from astraauth.service import (
    build_service_from_home,
    initialize_config_home,
    write_initial_admin_setup,
)


def build_deployment() -> tuple[Any, AuthConfig, Path]:
    from flask import Flask

    from astraauth.adapters import mount_oauth_flask

    home = Path(".astraauth")
    demo_admin_password = "change-me-now-local-demo-only"
    if not (home / "config.json").exists():
        initialize_config_home(
            home=home,
            project_name="AstraAuth",
            environment="prod",
            persistence_backend="sqlite",
            persistence_base_dir=str(home / "data"),
            issuer="https://auth.example.com",
            force=False,
        )
        write_initial_admin_setup(
            home=home,
            tenant_id="tenant-1",
            username="admin",
            password=demo_admin_password,
            email="admin@example.com",
        )

    config = AuthConfig.load(home=home)
    service = build_service_from_home(home=home)
    app = Flask(__name__)
    origin_policy = AdapterOriginPolicy(
        allowed_origins=frozenset({"https://app.example.com"}),
        allowed_callback_origins=frozenset({"https://app.example.com"}),
    )
    mount_oauth_flask(app, service.adapter, issuer=config.issuer, origin_policy=origin_policy)
    return app, config, home


def build_app() -> Any:
    app, _, _ = build_deployment()
    return app


def main() -> None:
    try:
        app, config, home = build_deployment()
    except ImportError:
        print("Install the Flask extra first: uv sync --extra flask")
        return

    print("Flask deployment app created")
    print(f"config_home={home}")
    print(f"issuer={config.issuer}")
    print("Demo admin password is local-only; replace it before any shared environment.")
    print("Origin policy allows https://app.example.com for browser-facing unsafe requests.")
    print("Run with your preferred WSGI server after installing Flask.")
    print(
        "Example: waitress-serve --call --listen=127.0.0.1:8000 'examples.08_flask_deployment:build_app'"
    )


if __name__ == "__main__":
    main()
