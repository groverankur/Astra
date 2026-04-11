from __future__ import annotations

import json
from pathlib import Path

import pytest
from astraauth_core.config import (
    DEFAULT_ASTRAAUTH_HOME,
    AuthConfig,
    PersistenceConfig,
    RelationalStoreConfig,
)


def test_default_auth_config_uses_inmemory_persistence() -> None:
    config = AuthConfig()

    config.validate()

    assert config.persistence.dsn_for("sessions") == "sqlite:///:memory:"
    assert config.persistence.dsn_for("sessions", mode="async") == "sqlite+aiosqlite:///:memory:"


def test_project_sqlite_persistence_layout_is_store_specific() -> None:
    config = AuthConfig.for_project(
        project_name="AstraAuth Core",
        environment="test",
        persistence_backend="sqlite",
        persistence_base_dir="runtime-data",
    )

    sessions_dsn = config.persistence.dsn_for("sessions")
    mfa_dsn = config.persistence.dsn_for("mfa")
    plugins_dsn = config.persistence.dsn_for("plugins")

    assert sessions_dsn.endswith("runtime-data/astraauth-core/test/sessions.db")
    assert mfa_dsn.endswith("runtime-data/astraauth-core/test/mfa.db")
    assert plugins_dsn.endswith("runtime-data/astraauth-core/test/plugins.db")


def test_postgres_persistence_builds_sync_and_async_dsns() -> None:
    persistence = PersistenceConfig(
        default_database=RelationalStoreConfig.postgres(
            database="astraauth_test",
            host="db.internal",
            username="astraauth",
            password="secret",
            options={"sslmode": "require"},
        )
    )

    assert (
        persistence.dsn_for("sessions")
        == "postgresql://astraauth:secret@db.internal:5432/astraauth_test?sslmode=require"
    )
    assert (
        persistence.dsn_for("sessions", mode="async")
        == "postgresql+psycopg://astraauth:secret@db.internal:5432/astraauth_test?sslmode=require"
    )


def test_database_validation_requires_host_for_network_backends() -> None:
    with pytest.raises(ValueError, match="host"):
        RelationalStoreConfig(backend="postgres", database="astraauth", host="")


def test_auth_config_can_save_encrypted_json_and_load_from_default_home(
    workspace_tmp_path: Path,
) -> None:
    config = AuthConfig.for_project(
        project_name="AstraAuth",
        environment="test",
        persistence_backend="postgres",
        persistence_host="db.local",
        persistence_username="astraauth",
        persistence_password="secret",
        persistence_database="astraauth_test",
    )

    config_path = config.save_json(home=workspace_tmp_path, encrypt_values=True)
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    assert payload["persistence"]["default_database"]["password"].startswith("enc::")

    loaded = AuthConfig.load(home=workspace_tmp_path)
    assert loaded.persistence.default_database.password == "secret"
    assert loaded.persistence.default_database.host == "db.local"


def test_auth_config_load_merges_dotenv_over_json(workspace_tmp_path: Path) -> None:
    config = AuthConfig.for_project(project_name="AstraAuth", environment="dev")
    config.save_json(home=workspace_tmp_path, encrypt_values=False)
    (workspace_tmp_path / ".env").write_text(
        "ASTRAAUTH_PROJECT_NAME=Overridden\n"
        "ASTRAAUTH_PERSISTENCE__DEFAULT_DATABASE__BACKEND=mysql\n"
        "ASTRAAUTH_PERSISTENCE__DEFAULT_DATABASE__DATABASE=astraauth_dev\n"
        "ASTRAAUTH_PERSISTENCE__DEFAULT_DATABASE__USERNAME=svc_user\n"
        "ASTRAAUTH_PERSISTENCE__DEFAULT_DATABASE__PASSWORD=svc_pass\n",
        encoding="utf-8",
    )

    loaded = AuthConfig.load(home=workspace_tmp_path)

    assert loaded.project_name == "Overridden"
    assert loaded.persistence.default_database.backend == "mysql"
    assert loaded.persistence.default_database.username == "svc_user"
    assert loaded.persistence.default_database.password == "svc_pass"


def test_default_home_constant_is_pathlike() -> None:
    assert isinstance(DEFAULT_ASTRAAUTH_HOME, Path)


def test_auth_config_can_update_json_path_with_glom(workspace_tmp_path: Path) -> None:
    config = AuthConfig.for_project(project_name="AstraAuth", environment="dev")
    config.save_json(home=workspace_tmp_path, encrypt_values=False)

    AuthConfig.update_json_path(
        "persistence.default_database.backend",
        "mysql",
        home=workspace_tmp_path,
        encrypt_values=False,
    )
    AuthConfig.update_json_path(
        "persistence.default_database.database",
        "astraauth_dev",
        home=workspace_tmp_path,
        encrypt_values=False,
    )

    loaded = AuthConfig.load(home=workspace_tmp_path)

    assert loaded.persistence.default_database.backend == "mysql"
    assert loaded.persistence.default_database.database == "astraauth_dev"
