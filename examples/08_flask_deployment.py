from __future__ import annotations

from pathlib import Path

from astraauth_core.config import AuthConfig
from astraauth_service import (
    build_service_from_home,
    initialize_config_home,
    write_initial_admin_setup,
)


def main() -> None:
    try:
        from flask import Flask
    except ImportError:
        print("Install the Flask extra first: uv sync --extra flask")
        return

    from astraauth_adapters import mount_oauth_flask

    home = Path(".astraauth")
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
            password="change-me-now",
            email="admin@example.com",
        )

    config = AuthConfig.load(home=home)
    service = build_service_from_home(home=home)
    app = Flask(__name__)
    mount_oauth_flask(app, service.adapter, issuer=config.issuer)

    print("Flask deployment app created")
    print(f"config_home={home}")
    print(f"issuer={config.issuer}")
    print("Run with your preferred WSGI server after installing Flask.")
    print("Example: waitress-serve --listen=127.0.0.1:8000 'examples.08_flask_deployment:app'")


if __name__ == "__main__":
    main()
