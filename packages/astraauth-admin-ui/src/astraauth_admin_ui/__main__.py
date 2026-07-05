from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
import uvicorn

from astraauth.core.config import DEFAULT_ASTRAAUTH_HOME
from astraauth_admin_ui.app import create_admin_app

app = typer.Typer(add_completion=False, help="Run Astra Netra, the Astra browser admin UI")


@app.callback(invoke_without_command=False)
def root_callback() -> None:
    """Astra Netra command group."""


@app.command()
def serve(
    home: Annotated[Path, typer.Option("--home")] = DEFAULT_ASTRAAUTH_HOME,
    host: Annotated[str, typer.Option("--host")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port")] = 8088,
) -> None:
    uvicorn.run(create_admin_app(home=home), host=host, port=port)


@app.command("version")
def version() -> None:
    print("astraauth-admin-ui")


def main() -> int:
    app()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
