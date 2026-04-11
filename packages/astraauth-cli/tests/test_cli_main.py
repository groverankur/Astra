# mypy: disable-error-code="no-untyped-def"

import importlib
import json
from pathlib import Path

from astraauth_cli.__main__ import main
from astraauth_core.config import AuthConfig
from astraauth_idp import FederationAuditRecord
from astraauth_service import build_service_from_home


def test_cli_version_command(monkeypatch, capsys) -> None:
    monkeypatch.setattr("sys.argv", ["astraauth", "version"])

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out.strip()


def test_cli_config_home_command(monkeypatch, capsys) -> None:
    monkeypatch.setattr("sys.argv", ["astraauth", "config-home"])

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert Path(captured.out.strip()).name == ".astraauth"


def test_cli_config_init_and_validate_config_command(monkeypatch, capsys, workspace_tmp_path: Path) -> None:
    monkeypatch.setattr(
        "sys.argv",
        [
            "astraauth",
            "config-init",
            "--home",
            str(workspace_tmp_path),
            "--environment",
            "test",
            "--persistence-backend",
            "sqlite",
            "--persistence-base-dir",
            str(workspace_tmp_path / "data"),
            "--issuer",
            "https://cli-validate.local",
            "--no-encrypt",
        ],
    )
    assert main() == 0
    assert capsys.readouterr().out.strip().startswith("config_path=")

    monkeypatch.setattr(
        "sys.argv",
        ["astraauth", "validate-config", "--home", str(workspace_tmp_path)],
    )

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Config OK:" in captured.out


def test_cli_health_and_inventory_commands(monkeypatch, capsys, workspace_tmp_path: Path) -> None:
    config = AuthConfig.for_project(
        project_name="AstraAuth",
        environment="test",
        persistence_backend="sqlite",
        persistence_base_dir=str(workspace_tmp_path / "data"),
        issuer="https://cli-health.local",
    )
    config.save_json(home=workspace_tmp_path, encrypt_values=False)
    monkeypatch.setattr(
        "sys.argv",
        ["astraauth", "health", "--home", str(workspace_tmp_path), "--json"],
    )

    exit_code = main()
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["ok"] is True
    assert payload["environment"] == "test"

    monkeypatch.setattr(
        "sys.argv",
        ["astraauth", "runtime-inventory", "--home", str(workspace_tmp_path), "--json"],
    )
    assert main() == 0
    inventory_payload = json.loads(capsys.readouterr().out)
    assert inventory_payload["environment"] == "test"
    assert "geo" in inventory_payload["registered_plugins"]


def test_cli_persistence_and_schema_commands(monkeypatch, capsys, workspace_tmp_path: Path) -> None:
    config = AuthConfig.for_project(
        project_name="AstraAuth",
        environment="test",
        persistence_backend="sqlite",
        persistence_base_dir=str(workspace_tmp_path / "data"),
    )
    config.save_json(home=workspace_tmp_path, encrypt_values=False)

    monkeypatch.setattr(
        "sys.argv",
        ["astraauth", "persistence-info", "--home", str(workspace_tmp_path), "--json"],
    )
    assert main() == 0
    persistence_payload = json.loads(capsys.readouterr().out)
    assert persistence_payload["stores"][0]["backend"] == "sqlite"

    monkeypatch.setattr(
        "sys.argv",
        ["astraauth", "schema-ensure", "--home", str(workspace_tmp_path), "--json"],
    )
    assert main() == 0
    schema_payload = json.loads(capsys.readouterr().out)
    assert schema_payload["auto_create_schema"] is True


def test_cli_key_bootstrap_and_audit_commands(monkeypatch, capsys, workspace_tmp_path: Path) -> None:
    config = AuthConfig.for_project(
        project_name="AstraAuth",
        environment="test",
        persistence_backend="sqlite",
        persistence_base_dir=str(workspace_tmp_path / "data"),
    )
    config.save_json(home=workspace_tmp_path, encrypt_values=False)

    monkeypatch.setattr(
        "sys.argv",
        ["astraauth", "key-jwks", "--home", str(workspace_tmp_path)],
    )
    assert main() == 0
    jwks_payload = json.loads(capsys.readouterr().out)
    assert "keys" in jwks_payload

    key_export_path = workspace_tmp_path / "exports" / "token-keys.json"
    monkeypatch.setattr(
        "sys.argv",
        ["astraauth", "key-export", "--home", str(workspace_tmp_path), "--output", str(key_export_path)],
    )
    assert main() == 0
    assert capsys.readouterr().out.strip().startswith("key_export=")

    monkeypatch.setattr(
        "sys.argv",
        ["astraauth", "key-rotate", "--home", str(workspace_tmp_path), "--use", "sig", "--json"],
    )
    assert main() == 0
    rotate_payload = json.loads(capsys.readouterr().out)
    assert rotate_payload["persisted"] is True
    assert "path" in rotate_payload

    monkeypatch.setattr(
        "sys.argv",
        ["astraauth", "key-import", "--home", str(workspace_tmp_path), "--input", str(key_export_path)],
    )
    assert main() == 0
    assert capsys.readouterr().out.strip().startswith("key_import=")

    monkeypatch.setattr(
        "sys.argv",
        [
            "astraauth",
            "bootstrap-token-create",
            "--home",
            str(workspace_tmp_path),
            "--ttl-seconds",
            "600",
            "--json",
        ],
    )
    assert main() == 0
    bootstrap_token_payload = json.loads(capsys.readouterr().out)
    assert bootstrap_token_payload["token"]

    monkeypatch.setattr(
        "sys.argv",
        [
            "astraauth",
            "init-admin",
            "--home",
            str(workspace_tmp_path),
            "--tenant-id",
            "tenant-1",
            "--username",
            "admin",
            "--password",
            "secret",
        ],
    )
    assert main() == 0
    captured = capsys.readouterr().out.strip()
    assert captured.startswith("bootstrap_manifest=")

    monkeypatch.setattr(
        "sys.argv",
        ["astraauth", "bootstrap-show", "--home", str(workspace_tmp_path), "--json"],
    )
    assert main() == 0
    bootstrap_payload = json.loads(capsys.readouterr().out)
    assert bootstrap_payload["admins"][0]["username"] == "admin"
    assert bootstrap_payload["setup_tokens"] == []
    assert bootstrap_payload["setup_locked"] is False

    monkeypatch.setattr(
        "sys.argv",
        ["astraauth", "bootstrap-token-purge", "--home", str(workspace_tmp_path)],
    )
    assert main() == 0
    assert capsys.readouterr().out.strip().startswith("bootstrap_manifest=")

    monkeypatch.setattr(
        "sys.argv",
        ["astraauth", "bootstrap-lockdown", "--home", str(workspace_tmp_path)],
    )
    assert main() == 0
    assert capsys.readouterr().out.strip().startswith("bootstrap_manifest=")

    monkeypatch.setattr(
        "sys.argv",
        ["astraauth", "bootstrap-show", "--home", str(workspace_tmp_path), "--json"],
    )
    assert main() == 0
    locked_payload = json.loads(capsys.readouterr().out)
    assert locked_payload["setup_locked"] is True

    service = build_service_from_home(home=workspace_tmp_path)
    service.oidc_audit.save(
        FederationAuditRecord.create(
            event_type="oidc.callback",
            provider_id="oidc-corp",
            tenant_id="tenant-1",
            status="succeeded",
        )
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "astraauth",
            "oidc-audit",
            "--home",
            str(workspace_tmp_path),
            "--tenant-id",
            "tenant-1",
            "--json",
        ],
    )
    assert main() == 0
    audit_payload = json.loads(capsys.readouterr().out)
    assert audit_payload["records"][0]["provider_id"] == "oidc-corp"


def test_cli_state_export_and_import_commands(monkeypatch, capsys, workspace_tmp_path: Path) -> None:
    config = AuthConfig.for_project(
        project_name="AstraAuth",
        environment="test",
        persistence_backend="sqlite",
        persistence_base_dir=str(workspace_tmp_path / "data"),
        issuer="https://state.local",
    )
    config.save_json(home=workspace_tmp_path, encrypt_values=False)

    monkeypatch.setattr(
        "sys.argv",
        [
            "astraauth",
            "init-admin",
            "--home",
            str(workspace_tmp_path),
            "--tenant-id",
            "tenant-1",
            "--username",
            "admin",
            "--password",
            "secret",
        ],
    )
    assert main() == 0
    _ = capsys.readouterr()

    export_path = workspace_tmp_path / "exports" / "state.json"
    monkeypatch.setattr(
        "sys.argv",
        ["astraauth", "state-export", "--home", str(workspace_tmp_path), "--output", str(export_path)],
    )
    assert main() == 0
    assert capsys.readouterr().out.strip().startswith("state_export=")

    AuthConfig.update_json_path("issuer", "https://mutated.local", home=workspace_tmp_path, encrypt_values=False)
    monkeypatch.setattr(
        "sys.argv",
        [
            "astraauth",
            "state-import",
            "--home",
            str(workspace_tmp_path),
            "--input",
            str(export_path),
            "--no-encrypt",
        ],
    )
    assert main() == 0
    output = capsys.readouterr().out
    assert "state_import_config=" in output
    assert "state_import_bootstrap=" in output
    assert build_service_from_home(home=workspace_tmp_path).token_manager._config.issuer == "https://state.local"


def test_cli_wizard_config_init_flow(monkeypatch, capsys, workspace_tmp_path: Path) -> None:
    cli_app = importlib.import_module("astraauth_cli.app")
    monkeypatch.setattr(cli_app, "select_action", lambda **_: "config-init")
    monkeypatch.setattr(cli_app, "prompt_text", lambda message, default=None, password=False: default or "AstraAuth")
    monkeypatch.setattr(cli_app, "prompt_environment", lambda default="dev": "test")
    monkeypatch.setattr(cli_app, "prompt_backend", lambda default="sqlite": "sqlite")
    monkeypatch.setattr(cli_app, "prompt_confirm", lambda message, default=False: False)
    monkeypatch.setattr(
        "sys.argv",
        ["astraauth", "wizard", "--home", str(workspace_tmp_path), "--no-tui"],
    )

    assert main() == 0
    assert "config_path=" in capsys.readouterr().out


def test_cli_wizard_exit(monkeypatch, capsys, workspace_tmp_path: Path) -> None:
    cli_app = importlib.import_module("astraauth_cli.app")
    monkeypatch.setattr(cli_app, "select_action", lambda **_: "exit")
    monkeypatch.setattr(
        "sys.argv",
        ["astraauth", "wizard", "--home", str(workspace_tmp_path), "--no-tui"],
    )

    assert main() == 0
    assert "Wizard exited." in capsys.readouterr().out


def test_cli_admin_ui_exit(monkeypatch, capsys, workspace_tmp_path: Path) -> None:
    config = AuthConfig.for_project(
        project_name="AstraAuth",
        environment="test",
        persistence_backend="sqlite",
        persistence_base_dir=str(workspace_tmp_path / "data"),
    )
    config.save_json(home=workspace_tmp_path, encrypt_values=False)
    monkeypatch.setattr("astraauth_cli.admin_ui.select_action", lambda **_: "exit")
    monkeypatch.setattr(
        "sys.argv",
        ["astraauth", "admin-ui", "--home", str(workspace_tmp_path), "--no-tui"],
    )

    assert main() == 0
    output = capsys.readouterr().out
    assert "Astra Netra" in output


def test_cli_backup_verify_doctor_and_admin_audit_commands(monkeypatch, capsys, workspace_tmp_path: Path) -> None:
    config = AuthConfig.for_project(
        project_name="AstraAuth",
        environment="test",
        persistence_backend="sqlite",
        persistence_base_dir=str(workspace_tmp_path / "data"),
        issuer="https://doctor.local",
    )
    config.save_json(home=workspace_tmp_path, encrypt_values=False)

    monkeypatch.setattr(
        "sys.argv",
        [
            "astraauth",
            "init-admin",
            "--home",
            str(workspace_tmp_path),
            "--tenant-id",
            "tenant-1",
            "--username",
            "admin",
            "--password",
            "secret",
        ],
    )
    assert main() == 0
    _ = capsys.readouterr()

    bootstrap_export = workspace_tmp_path / "exports" / "bootstrap.json"
    monkeypatch.setattr(
        "sys.argv",
        ["astraauth", "bootstrap-export", "--home", str(workspace_tmp_path), "--output", str(bootstrap_export)],
    )
    assert main() == 0
    _ = capsys.readouterr()

    monkeypatch.setattr(
        "sys.argv",
        ["astraauth", "backup-verify", "--home", str(workspace_tmp_path), "--input", str(bootstrap_export), "--json"],
    )
    assert main() == 0
    backup_payload = json.loads(capsys.readouterr().out)
    assert backup_payload["valid"] is True
    assert backup_payload["artifact_type"] == "bootstrap"

    monkeypatch.setattr(
        "sys.argv",
        ["astraauth", "doctor", "--home", str(workspace_tmp_path), "--json"],
    )
    assert main() == 0
    doctor_payload = json.loads(capsys.readouterr().out)
    assert doctor_payload["config_valid"] is True
    assert doctor_payload["bootstrap_valid"] is True

    from astraauth_service import record_admin_action

    record_admin_action(
        event_type="admin.test",
        status="succeeded",
        details={"source": "cli-test"},
        home=workspace_tmp_path,
    )
    monkeypatch.setattr(
        "sys.argv",
        ["astraauth", "admin-audit", "--home", str(workspace_tmp_path), "--json"],
    )
    assert main() == 0
    admin_audit_payload = json.loads(capsys.readouterr().out)
    assert admin_audit_payload["records"][-1]["event_type"] == "admin.test"


def test_cli_observability_command(monkeypatch, capsys, workspace_tmp_path: Path) -> None:
    config = AuthConfig.for_project(
        project_name="AstraAuth",
        environment="test",
        persistence_backend="sqlite",
        persistence_base_dir=str(workspace_tmp_path / "data"),
    )
    config.save_json(home=workspace_tmp_path, encrypt_values=False)

    monkeypatch.setattr(
        "sys.argv",
        ["astraauth", "observability", "--home", str(workspace_tmp_path), "--json"],
    )
    assert main() == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["service_name"] == "astraauth"
    assert payload["correlation_header_name"] == "X-Correlation-ID"


def test_cli_bootstrap_lockdown_blocks_new_setup_tokens(
    monkeypatch, capsys, workspace_tmp_path: Path
) -> None:
    config = AuthConfig.for_project(
        project_name="AstraAuth",
        environment="test",
        persistence_backend="sqlite",
        persistence_base_dir=str(workspace_tmp_path / "data"),
    )
    config.save_json(home=workspace_tmp_path, encrypt_values=False)

    monkeypatch.setattr(
        "sys.argv",
        [
            "astraauth",
            "init-admin",
            "--home",
            str(workspace_tmp_path),
            "--tenant-id",
            "tenant-1",
            "--username",
            "admin",
            "--password",
            "secret",
        ],
    )
    assert main() == 0
    _ = capsys.readouterr()

    monkeypatch.setattr(
        "sys.argv",
        ["astraauth", "bootstrap-lockdown", "--home", str(workspace_tmp_path)],
    )
    assert main() == 0
    _ = capsys.readouterr()

    monkeypatch.setattr(
        "sys.argv",
        [
            "astraauth",
            "bootstrap-token-create",
            "--home",
            str(workspace_tmp_path),
            "--ttl-seconds",
            "600",
        ],
    )
    assert main() != 0
