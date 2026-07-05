from pathlib import Path
from typing import Any

from astraauth_admin_ui.__main__ import app
from typer.testing import CliRunner


def test_admin_ui_cli_exposes_serve_command(monkeypatch: Any, workspace_tmp_path: Path) -> None:
    runner = CliRunner()

    captured: dict[str, object] = {}

    def fake_run(application: Any, host: str, port: int) -> None:
        captured["app"] = application
        captured["host"] = host
        captured["port"] = port

    monkeypatch.setattr("astraauth_admin_ui.__main__.uvicorn.run", fake_run)

    result = runner.invoke(
        app,
        ["serve", "--home", str(workspace_tmp_path), "--host", "127.0.0.1", "--port", "8088"],
    )

    assert result.exit_code == 0
    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 8088


def test_admin_ui_cli_version_command() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert "astraauth-admin-ui" in result.stdout
