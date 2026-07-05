from __future__ import annotations

from pathlib import Path

from astraauth_admin_ui import create_admin_app

from astraauth.service import initialize_config_home, operator_setup_status

HOME = Path(".astraauth")
HOST = "127.0.0.1"
PORT = 8088

app = create_admin_app(home=HOME)


def ensure_local_home() -> None:
    if (HOME / "config.json").exists():
        return
    initialize_config_home(
        home=HOME,
        project_name="AstraAuth",
        environment="dev",
        persistence_backend="sqlite",
        persistence_base_dir=str(HOME / "data"),
        issuer=f"http://{HOST}:{PORT}",
        force=False,
    )


def main() -> None:
    try:
        import uvicorn
    except ImportError:
        print("Install admin UI runtime dependencies first: uv sync --all-groups")
        return

    ensure_local_home()
    setup = operator_setup_status(home=HOME)
    print("Astra Netra admin UI")
    print(f"home={HOME.resolve()}")
    print(f"url=http://{HOST}:{PORT}/")
    print(f"setup_required={setup.setup_required}")
    print("Local demo defaults bind to 127.0.0.1 only. Do not expose this example directly.")
    print("Use the CLI/admin setup token flow to create the first operator account.")
    uvicorn.run(app, host=HOST, port=PORT, reload=False)


if __name__ == "__main__":
    main()
