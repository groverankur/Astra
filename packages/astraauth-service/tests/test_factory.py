from pathlib import Path

from astraauth_core.config import (
    AuthConfig,
    IDPConfig,
    OIDCProviderSettings,
    PersistenceConfig,
    RelationalStoreConfig,
)
from astraauth_core.mfa import SQLMFAChallengeStore
from astraauth_core.plugins import SQLTenantPluginRegistryStore
from astraauth_core.sessions import SQLSessionStore
from astraauth_idp import FederationAuditRecord, SQLOIDCLoginStateRepository
from astraauth_service import (
    BootstrapManifest,
    bootstrap_service,
    build_inmemory_service,
    build_service,
    build_service_from_home,
    ensure_runtime_schema,
    export_bootstrap_manifest,
    export_public_jwks,
    export_runtime_config,
    export_runtime_state_bundle,
    export_token_key_state,
    import_bootstrap_manifest,
    import_runtime_config,
    import_runtime_state_bundle,
    import_token_key_state,
    initialize_config_home,
    list_oidc_audit_records,
    load_auth_config,
    load_bootstrap_manifest,
    persistence_report,
    refresh_service_from_home,
    reload_auth_config,
    rotate_runtime_keys,
    runtime_health_report,
    runtime_inventory_report,
    runtime_observability_report,
    validate_runtime_config,
    write_initial_admin_setup,
)


def test_build_inmemory_service_creates_adapter() -> None:
    svc = build_inmemory_service()
    assert svc.adapter is not None


def test_build_service_uses_configured_sqlite_persistence(workspace_tmp_path: Path) -> None:
    config = AuthConfig(
        project_name="AstraAuth",
        environment="test",
        issuer="astraauth.local",
        dev_mode=True,
        persistence=PersistenceConfig(
            default_database=RelationalStoreConfig.sqlite_file(str(workspace_tmp_path / "shared.db")),
            sessions_database=RelationalStoreConfig.sqlite_file(str(workspace_tmp_path / "sessions.db")),
            mfa_database=RelationalStoreConfig.sqlite_file(str(workspace_tmp_path / "mfa.db")),
            plugins_database=RelationalStoreConfig.sqlite_file(str(workspace_tmp_path / "plugins.db")),
            idp_database=RelationalStoreConfig.sqlite_file(str(workspace_tmp_path / "idp.db")),
        ),
        idp=IDPConfig(
            oidc_providers=(
                OIDCProviderSettings(
                    provider_id="oidc-corp",
                    issuer="https://issuer.example.com",
                    client_id="oidc-client",
                    client_secret="secret",
                ),
            )
        ),
    )
    svc = build_service(config=config, default_plugins_enabled=False)

    assert isinstance(svc.sessions, SQLSessionStore)
    assert isinstance(svc.mfa_challenges, SQLMFAChallengeStore)
    assert isinstance(svc.plugin_runtime._registry_store, SQLTenantPluginRegistryStore)
    assert isinstance(svc.oidc_login_states, SQLOIDCLoginStateRepository)


def test_bootstrap_service_loads_default_home_config(workspace_tmp_path: Path) -> None:
    config = AuthConfig.for_project(
        project_name="AstraAuth",
        environment="test",
        persistence_backend="sqlite",
        persistence_base_dir=str(workspace_tmp_path / "runtime"),
    )
    config.save_json(home=workspace_tmp_path, encrypt_values=True)

    svc = build_service_from_home(home=workspace_tmp_path)
    bootstrapped = bootstrap_service(home=workspace_tmp_path)

    assert isinstance(svc.sessions, SQLSessionStore)
    assert bootstrapped.adapter is not None


def test_reload_and_refresh_service_pick_up_updated_home_config(workspace_tmp_path: Path) -> None:
    config = AuthConfig.for_project(
        project_name="AstraAuth",
        environment="dev",
        persistence_backend="sqlite",
        persistence_base_dir=str(workspace_tmp_path / "runtime"),
    )
    config.save_json(home=workspace_tmp_path, encrypt_values=False)

    loaded = load_auth_config(home=workspace_tmp_path)
    AuthConfig.update_json_path(
        "issuer",
        "https://updated.local",
        home=workspace_tmp_path,
        encrypt_values=False,
    )

    reloaded = reload_auth_config(loaded, home=workspace_tmp_path)
    refreshed = refresh_service_from_home(current_config=loaded, home=workspace_tmp_path)

    assert reloaded.issuer == "https://updated.local"
    assert refreshed.token_manager._config.issuer == "https://updated.local"


def test_validate_runtime_config_and_health_report(workspace_tmp_path: Path) -> None:
    config = AuthConfig.for_project(
        project_name="AstraAuth",
        environment="test",
        persistence_backend="sqlite",
        persistence_base_dir=str(workspace_tmp_path / "runtime"),
        issuer="https://health.local",
    )
    config.save_json(home=workspace_tmp_path, encrypt_values=False)

    validated = validate_runtime_config(home=workspace_tmp_path)
    report = runtime_health_report(home=workspace_tmp_path)

    assert validated.issuer == "https://health.local"
    assert report.ok is True
    assert report.persistence_backends["sessions"] == "sqlite"
    assert report.environment == "test"


def test_persistence_reports_and_key_helpers(workspace_tmp_path: Path) -> None:
    config = AuthConfig.for_project(
        project_name="AstraAuth",
        environment="test",
        persistence_backend="sqlite",
        persistence_base_dir=str(workspace_tmp_path / "runtime"),
    )
    config.save_json(home=workspace_tmp_path, encrypt_values=False)

    persistence = persistence_report(home=workspace_tmp_path)
    ensured = ensure_runtime_schema(home=workspace_tmp_path)
    jwks = export_public_jwks(home=workspace_tmp_path)
    persisted_path, rotated = rotate_runtime_keys(home=workspace_tmp_path, use="sig")

    assert persistence.stores[0].backend == "sqlite"
    assert ensured.auto_create_schema is True
    assert persisted_path.exists()
    assert len(jwks) >= 1
    assert len(rotated) >= len(jwks)


def test_initial_admin_bootstrap_manifest_is_applied(workspace_tmp_path: Path) -> None:
    config = AuthConfig.for_project(
        project_name="AstraAuth",
        environment="test",
        persistence_backend="sqlite",
        persistence_base_dir=str(workspace_tmp_path / "runtime"),
    )
    config.save_json(home=workspace_tmp_path, encrypt_values=False)
    write_initial_admin_setup(
        home=workspace_tmp_path,
        tenant_id="tenant-1",
        username="admin",
        password="secret",
        email="admin@example.com",
    )

    manifest = load_bootstrap_manifest(home=workspace_tmp_path)
    svc = build_service_from_home(home=workspace_tmp_path)

    assert isinstance(manifest, BootstrapManifest)
    assert manifest.admins[0].username == "admin"
    assert svc.subjects.get_subject("local:tenant-1:admin") is not None
    assignment = svc.assignments.get_assignments("local:tenant-1:admin", "tenant-1")
    assert assignment is not None
    assert assignment.roles == {"admin"}


def test_initialize_config_and_runtime_inventory(workspace_tmp_path: Path) -> None:
    config_path = initialize_config_home(
        home=workspace_tmp_path,
        project_name="AstraAuth",
        environment="test",
        persistence_backend="sqlite",
        persistence_base_dir=str(workspace_tmp_path / "runtime"),
        issuer="https://inventory.local",
        encrypt_values=False,
    )

    inventory = runtime_inventory_report(home=workspace_tmp_path)

    assert config_path.exists()
    assert inventory.environment == "test"
    assert "geo" in inventory.registered_plugins
    assert inventory.bootstrap_admin_count == 0


def test_list_oidc_audit_records_from_home(workspace_tmp_path: Path) -> None:
    config = AuthConfig.for_project(
        project_name="AstraAuth",
        environment="test",
        persistence_backend="sqlite",
        persistence_base_dir=str(workspace_tmp_path / "runtime"),
    )
    config.save_json(home=workspace_tmp_path, encrypt_values=False)
    svc = build_service_from_home(home=workspace_tmp_path)
    svc.oidc_audit.save(
        FederationAuditRecord.create(
            event_type="oidc.callback",
            provider_id="oidc-corp",
            tenant_id="tenant-1",
            status="succeeded",
        )
    )

    records = list_oidc_audit_records(home=workspace_tmp_path, tenant_id="tenant-1")

    assert len(records) == 1
    assert records[0]["provider_id"] == "oidc-corp"


def test_export_and_import_runtime_config(workspace_tmp_path: Path) -> None:
    config = AuthConfig.for_project(
        project_name="AstraAuth",
        environment="test",
        persistence_backend="sqlite",
        persistence_base_dir=str(workspace_tmp_path / "runtime"),
        issuer="https://export.local",
    )
    config.save_json(home=workspace_tmp_path, encrypt_values=False)
    export_path = workspace_tmp_path / "exports" / "config.json"

    exported = export_runtime_config(home=workspace_tmp_path, output_path=export_path)
    AuthConfig.update_json_path("issuer", "https://mutated.local", home=workspace_tmp_path, encrypt_values=False)
    imported = import_runtime_config(
        home=workspace_tmp_path,
        input_path=export_path,
        encrypt_values=False,
    )

    assert exported.exists()
    assert imported.exists()
    assert load_auth_config(home=workspace_tmp_path).issuer == "https://export.local"


def test_export_and_import_bootstrap_manifest(workspace_tmp_path: Path) -> None:
    config = AuthConfig.for_project(
        project_name="AstraAuth",
        environment="test",
        persistence_backend="sqlite",
        persistence_base_dir=str(workspace_tmp_path / "runtime"),
    )
    config.save_json(home=workspace_tmp_path, encrypt_values=False)
    write_initial_admin_setup(
        home=workspace_tmp_path,
        tenant_id="tenant-1",
        username="admin",
        password="secret",
    )
    export_path = workspace_tmp_path / "exports" / "bootstrap.json"

    exported = export_bootstrap_manifest(home=workspace_tmp_path, output_path=export_path)
    imported = import_bootstrap_manifest(home=workspace_tmp_path, input_path=export_path, merge=False)

    assert exported.exists()
    assert imported.exists()
    assert load_bootstrap_manifest(home=workspace_tmp_path).admins[0].username == "admin"


def test_export_and_import_runtime_state_bundle(workspace_tmp_path: Path) -> None:
    config = AuthConfig.for_project(
        project_name="AstraAuth",
        environment="test",
        persistence_backend="sqlite",
        persistence_base_dir=str(workspace_tmp_path / "runtime"),
        issuer="https://bundle.local",
    )
    config.save_json(home=workspace_tmp_path, encrypt_values=False)
    write_initial_admin_setup(
        home=workspace_tmp_path,
        tenant_id="tenant-1",
        username="admin",
        password="secret",
    )
    export_path = workspace_tmp_path / "exports" / "state-bundle.json"

    exported = export_runtime_state_bundle(home=workspace_tmp_path, output_path=export_path)
    AuthConfig.update_json_path("issuer", "https://mutated.local", home=workspace_tmp_path, encrypt_values=False)
    imported_config_path, imported_bootstrap_path = import_runtime_state_bundle(
        home=workspace_tmp_path,
        input_path=export_path,
        encrypt_values=False,
    )

    assert exported.exists()
    assert imported_config_path.exists()
    assert imported_bootstrap_path.exists()
    assert load_auth_config(home=workspace_tmp_path).issuer == "https://bundle.local"
    assert load_bootstrap_manifest(home=workspace_tmp_path).admins[0].username == "admin"


def test_export_and_import_token_key_state(workspace_tmp_path: Path) -> None:
    config = AuthConfig.for_project(
        project_name="AstraAuth",
        environment="test",
        persistence_backend="sqlite",
        persistence_base_dir=str(workspace_tmp_path / "runtime"),
    )
    config.save_json(home=workspace_tmp_path, encrypt_values=False)
    _, rotated = rotate_runtime_keys(home=workspace_tmp_path, use="sig")
    export_path = workspace_tmp_path / "exports" / "token-keys.json"

    exported = export_token_key_state(home=workspace_tmp_path, output_path=export_path)
    imported = import_token_key_state(home=workspace_tmp_path, input_path=export_path)
    jwks = export_public_jwks(home=workspace_tmp_path)

    assert exported.exists()
    assert imported.exists()
    assert len(jwks) == len(rotated)


def test_verify_backup_artifact_and_runtime_diagnostics(workspace_tmp_path: Path) -> None:
    config = AuthConfig.for_project(
        project_name="AstraAuth",
        environment="test",
        persistence_backend="sqlite",
        persistence_base_dir=str(workspace_tmp_path / "runtime"),
        issuer="https://diagnostics.local",
    )
    config.save_json(home=workspace_tmp_path, encrypt_values=False)
    write_initial_admin_setup(
        home=workspace_tmp_path,
        tenant_id="tenant-1",
        username="admin",
        password="secret",
    )
    config_export = workspace_tmp_path / "exports" / "config.json"
    bootstrap_export = workspace_tmp_path / "exports" / "bootstrap.json"
    state_export = workspace_tmp_path / "exports" / "state.json"
    key_export = workspace_tmp_path / "exports" / "token-keys.json"

    export_runtime_config(home=workspace_tmp_path, output_path=config_export)
    export_bootstrap_manifest(home=workspace_tmp_path, output_path=bootstrap_export)
    export_runtime_state_bundle(home=workspace_tmp_path, output_path=state_export)
    export_token_key_state(home=workspace_tmp_path, output_path=key_export)

    from astraauth_service import runtime_diagnostics_report, verify_backup_artifact

    config_report = verify_backup_artifact(home=workspace_tmp_path, input_path=config_export)
    bootstrap_report = verify_backup_artifact(home=workspace_tmp_path, input_path=bootstrap_export)
    state_report = verify_backup_artifact(home=workspace_tmp_path, input_path=state_export)
    key_report = verify_backup_artifact(home=workspace_tmp_path, input_path=key_export)
    diagnostics = runtime_diagnostics_report(home=workspace_tmp_path)

    assert config_report.valid is True
    assert config_report.artifact_type == "config"
    assert bootstrap_report.valid is True
    assert bootstrap_report.artifact_type == "bootstrap"
    assert state_report.valid is True
    assert state_report.artifact_type == "state_bundle"
    assert key_report.valid is True
    assert key_report.artifact_type == "token_keys"
    assert diagnostics.config_valid is True
    assert diagnostics.token_keys_valid is True
    assert diagnostics.bootstrap_valid is True
    assert diagnostics.bootstrap_admin_count == 1


def test_runtime_diagnostics_reports_missing_config(workspace_tmp_path: Path) -> None:
    from astraauth_service import runtime_diagnostics_report

    diagnostics = runtime_diagnostics_report(home=workspace_tmp_path)

    assert diagnostics.ok is False
    assert "missing_config" in diagnostics.issues


def test_runtime_observability_report_tracks_key_operations(workspace_tmp_path: Path) -> None:
    config = AuthConfig.for_project(
        project_name="AstraAuth",
        environment="test",
        persistence_backend="sqlite",
        persistence_base_dir=str(workspace_tmp_path / "runtime"),
    )
    config.save_json(home=workspace_tmp_path, encrypt_values=False)

    export_path = workspace_tmp_path / "exports" / "token-keys.json"
    export_token_key_state(home=workspace_tmp_path, output_path=export_path)
    import_token_key_state(home=workspace_tmp_path, input_path=export_path)
    rotate_runtime_keys(home=workspace_tmp_path, use="sig")

    report = runtime_observability_report(home=workspace_tmp_path)
    counters = {counter.name: counter.value for counter in report.counters}

    assert report.metrics_enabled is True
    assert report.structured_logging_enabled is True
    assert counters["key.exports"] == 1
    assert counters["key.imports"] == 1
    assert counters["key.rotations"] == 1
    assert report.metrics_path.exists()
    assert report.log_path.exists()
