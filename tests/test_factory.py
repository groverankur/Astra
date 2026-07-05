import json
import time
from collections.abc import Callable
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from astraauth.core.config import (
    AuthConfig,
    IDPConfig,
    OIDCProviderSettings,
    PersistenceConfig,
    RelationalStoreConfig,
)
from astraauth.core.mfa import SQLMFAChallengeStore
from astraauth.core.oauth.password import hash_password_legacy_sha256
from astraauth.core.plugins import SQLTenantPluginRegistryStore
from astraauth.core.sessions import SQLSessionStore
from astraauth.idp import FederationAuditRecord, SQLOIDCLoginStateRepository
from astraauth.plugins import PluginTrustPolicy
from astraauth.plugins.contracts import (
    ColumnExtension,
    EndpointExtension,
    HookName,
    PluginManifest,
    TableExtension,
)
from astraauth.service import (
    BootstrapManifest,
    authenticate_operator_admin,
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
    redact_value,
    refresh_service_from_home,
    reload_auth_config,
    rotate_config_settings_key,
    rotate_runtime_keys,
    runtime_diagnostics_report,
    runtime_health_report,
    runtime_inventory_report,
    runtime_observability_report,
    runtime_security_report,
    validate_runtime_config,
    verify_backup_artifact,
    write_initial_admin_setup,
)


def _write_rsa_keypair(directory: Path) -> tuple[Path, Path]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_path = directory / "recipient-private.pem"
    public_path = directory / "recipient-public.pem"
    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return public_path, private_path


def test_build_inmemory_service_creates_adapter() -> None:
    svc = build_inmemory_service()
    assert svc.adapter is not None


def test_build_service_enforces_plugin_trust_policy() -> None:
    class TrustPlugin:
        name = "trusted"
        order = 1

        def hooks(self) -> dict[HookName, Callable[[dict[str, object]], dict[str, object] | None]]:
            return {}

        def register_endpoints(self) -> tuple[EndpointExtension, ...]:
            return ()

        def register_tables(self) -> tuple[TableExtension, ...]:
            return ()

        def register_columns(self) -> tuple[ColumnExtension, ...]:
            return ()

    service = build_service(
        default_plugins_enabled=False,
        plugin_trust_policy=PluginTrustPolicy(
            allowed_plugins=frozenset({"trusted"}),
            allowed_versions={"trusted": ">=1.0,<2.0"},
        ),
    )

    service.register_plugin(
        TrustPlugin(),
        manifest=PluginManifest(name="trusted", version="1.2.0", digest="sha256:trusted"),
    )

    assert "trusted" in service.plugin_runtime.registered_plugin_names()


def test_build_service_uses_configured_sqlite_persistence(workspace_tmp_path: Path) -> None:
    config = AuthConfig(
        project_name="AstraAuth",
        environment="test",
        issuer="astraauth.local",
        dev_mode=True,
        persistence=PersistenceConfig(
            default_database=RelationalStoreConfig.sqlite_file(
                str(workspace_tmp_path / "shared.db")
            ),
            sessions_database=RelationalStoreConfig.sqlite_file(
                str(workspace_tmp_path / "sessions.db")
            ),
            mfa_database=RelationalStoreConfig.sqlite_file(str(workspace_tmp_path / "mfa.db")),
            plugins_database=RelationalStoreConfig.sqlite_file(
                str(workspace_tmp_path / "plugins.db")
            ),
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


def test_redaction_masks_secret_fields_and_dsn_passwords() -> None:
    payload = {
        "issuer": "https://auth.example.com",
        "dsn": "postgresql://astraauth:secret@db.internal:5432/astraauth?sslmode=require",
        "nested": {
            "client_secret": "oidc-secret",
            "password_hash": "$argon2id$v=19$hash",
            "token_hash": "abcdef",
        },
    }

    redacted = redact_value(payload)

    assert redacted["issuer"] == "https://auth.example.com"
    assert (
        redacted["dsn"]
        == "postgresql://astraauth:%5BREDACTED%5D@db.internal:5432/astraauth?sslmode=require"
    )
    assert redacted["nested"]["client_secret"] == "[REDACTED]"
    assert redacted["nested"]["password_hash"] == "[REDACTED]"
    assert redacted["nested"]["token_hash"] == "[REDACTED]"


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


def test_bootstrap_admin_login_upgrades_legacy_password_hash(workspace_tmp_path: Path) -> None:
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
    manifest = load_bootstrap_manifest(home=workspace_tmp_path)
    legacy_manifest = BootstrapManifest(
        admins=tuple(
            type(admin)(
                tenant_id=admin.tenant_id,
                username=admin.username,
                password_hash=hash_password_legacy_sha256("secret"),
                subject_id=admin.subject_id,
                role_name=admin.role_name,
                client_id=admin.client_id,
                email=admin.email,
            )
            for admin in manifest.admins
        ),
        setup_tokens=manifest.setup_tokens,
        setup_locked=manifest.setup_locked,
    )
    from astraauth.service import save_bootstrap_manifest

    save_bootstrap_manifest(legacy_manifest, home=workspace_tmp_path)

    principal = authenticate_operator_admin(
        home=workspace_tmp_path,
        tenant_id="tenant-1",
        username="admin",
        password="secret",
    )
    upgraded_manifest = load_bootstrap_manifest(home=workspace_tmp_path)

    assert principal.username == "admin"
    assert upgraded_manifest.admins[0].password_hash.startswith("$argon2")


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


def test_runtime_security_report_includes_throttle_and_plugin_audit_signals(
    workspace_tmp_path: Path,
) -> None:
    config = AuthConfig.for_project(
        project_name="AstraAuth",
        environment="test",
        persistence_backend="sqlite",
        persistence_base_dir=str(workspace_tmp_path / "runtime"),
    )
    config.save_json(home=workspace_tmp_path, encrypt_values=False)
    service = build_service_from_home(home=workspace_tmp_path)

    class AuditPlugin:
        name = "audit"
        order = 5

        def hooks(self) -> dict[HookName, Callable[[dict[str, object]], dict[str, object] | None]]:
            return {"auth.pre_authenticate": lambda payload: {"audit_checked": True}}

        def register_endpoints(self) -> tuple[EndpointExtension, ...]:
            return ()

        def register_tables(self) -> tuple[TableExtension, ...]:
            return ()

        def register_columns(self) -> tuple[ColumnExtension, ...]:
            return ()

    service.plugin_runtime.register(AuditPlugin())
    service.plugin_runtime.enable_for_tenant(tenant_id="tenant-1", plugin_name="audit")
    service.plugin_runtime.execute_hook(
        hook="auth.pre_authenticate",
        tenant_id="tenant-1",
        payload={"username": "alice"},
        fail_closed=False,
    )
    now = time.monotonic()
    service.throttle_store.record(
        bucket="oauth-token|127.0.0.1|tenant-1|alice",
        max_events=1,
        window_seconds=300.0,
        block_seconds=600.0,
        now=now,
    )
    service.throttle_store.record(
        bucket="oauth-token|127.0.0.1|tenant-1|alice",
        max_events=1,
        window_seconds=300.0,
        block_seconds=600.0,
        now=now + 1,
    )

    report = runtime_security_report(home=workspace_tmp_path)

    assert report.runtime_throttle.bucket_count >= 1
    assert report.runtime_throttle.blocked_bucket_count >= 1
    assert report.plugin_audit_record_count >= 1
    assert any(record.plugin_name == "audit" for record in report.recent_plugin_audit_records)


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
    AuthConfig.update_json_path(
        "issuer", "https://mutated.local", home=workspace_tmp_path, encrypt_values=False
    )
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
    payload = json.loads(export_path.read_text(encoding="utf-8"))
    imported = import_bootstrap_manifest(
        home=workspace_tmp_path, input_path=export_path, merge=False
    )

    assert exported.exists()
    assert payload["artifact_type"] == "astraauth.encrypted_bootstrap_manifest"
    assert "encrypted_payload" in payload
    assert "password_hash" not in export_path.read_text(encoding="utf-8")
    assert imported.exists()
    assert load_bootstrap_manifest(home=workspace_tmp_path).admins[0].username == "admin"


def test_bootstrap_manifest_plaintext_export_requires_explicit_unsafe_flag(
    workspace_tmp_path: Path,
) -> None:
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
    export_path = workspace_tmp_path / "exports" / "bootstrap-plain.json"

    export_bootstrap_manifest(
        home=workspace_tmp_path,
        output_path=export_path,
        unsafe_plaintext=True,
    )
    payload = json.loads(export_path.read_text(encoding="utf-8"))

    assert payload["admins"][0]["username"] == "admin"
    assert "password_hash" in payload["admins"][0]


def test_bootstrap_manifest_recipient_key_export_import_and_verify(
    workspace_tmp_path: Path,
) -> None:
    public_key_path, private_key_path = _write_rsa_keypair(workspace_tmp_path)
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
    export_path = workspace_tmp_path / "exports" / "bootstrap-recipient.json"

    export_bootstrap_manifest(
        home=workspace_tmp_path,
        output_path=export_path,
        recipient_public_key_path=public_key_path,
    )
    payload = json.loads(export_path.read_text(encoding="utf-8"))

    assert payload["algorithm"] == "rsa-oaep-sha256+fernet"
    assert "encrypted_key" in payload
    assert "password_hash" not in export_path.read_text(encoding="utf-8")

    try:
        import_bootstrap_manifest(home=workspace_tmp_path, input_path=export_path)
    except ValueError as exc:
        assert "recipient private key is required" in str(exc)
    else:
        raise AssertionError("recipient-key encrypted bootstrap import should require private key")

    report = verify_backup_artifact(
        home=workspace_tmp_path,
        input_path=export_path,
        recipient_private_key_path=private_key_path,
    )
    imported = import_bootstrap_manifest(
        home=workspace_tmp_path,
        input_path=export_path,
        recipient_private_key_path=private_key_path,
    )

    assert report.valid is True
    assert report.artifact_type == "bootstrap"
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
    payload = json.loads(export_path.read_text(encoding="utf-8"))
    AuthConfig.update_json_path(
        "issuer", "https://mutated.local", home=workspace_tmp_path, encrypt_values=False
    )
    imported_config_path, imported_bootstrap_path = import_runtime_state_bundle(
        home=workspace_tmp_path,
        input_path=export_path,
        encrypt_values=False,
    )

    assert exported.exists()
    assert payload["bootstrap"]["artifact_type"] == "astraauth.encrypted_bootstrap_manifest"
    assert "password_hash" not in export_path.read_text(encoding="utf-8")
    assert imported_config_path.exists()
    assert imported_bootstrap_path.exists()
    assert load_auth_config(home=workspace_tmp_path).issuer == "https://bundle.local"
    assert load_bootstrap_manifest(home=workspace_tmp_path).admins[0].username == "admin"


def test_runtime_state_bundle_recipient_key_bootstrap_content(workspace_tmp_path: Path) -> None:
    public_key_path, private_key_path = _write_rsa_keypair(workspace_tmp_path)
    config = AuthConfig.for_project(
        project_name="AstraAuth",
        environment="test",
        persistence_backend="sqlite",
        persistence_base_dir=str(workspace_tmp_path / "runtime"),
        issuer="https://bundle-recipient.local",
    )
    config.save_json(home=workspace_tmp_path, encrypt_values=False)
    write_initial_admin_setup(
        home=workspace_tmp_path,
        tenant_id="tenant-1",
        username="admin",
        password="secret",
    )
    export_path = workspace_tmp_path / "exports" / "state-recipient.json"

    export_runtime_state_bundle(
        home=workspace_tmp_path,
        output_path=export_path,
        recipient_public_key_path=public_key_path,
    )
    payload = json.loads(export_path.read_text(encoding="utf-8"))

    assert payload["bootstrap"]["algorithm"] == "rsa-oaep-sha256+fernet"
    assert "password_hash" not in export_path.read_text(encoding="utf-8")

    import_runtime_state_bundle(
        home=workspace_tmp_path,
        input_path=export_path,
        encrypt_values=False,
        recipient_private_key_path=private_key_path,
    )
    report = verify_backup_artifact(
        home=workspace_tmp_path,
        input_path=export_path,
        recipient_private_key_path=private_key_path,
    )

    assert report.valid is True
    assert report.artifact_type == "state_bundle"
    assert load_auth_config(home=workspace_tmp_path).issuer == "https://bundle-recipient.local"


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

    from astraauth.service import runtime_diagnostics_report, verify_backup_artifact

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
    from astraauth.service import runtime_diagnostics_report

    diagnostics = runtime_diagnostics_report(home=workspace_tmp_path)

    assert diagnostics.ok is False
    assert "missing_config" in diagnostics.issues


def test_runtime_diagnostics_reports_config_key_custody(workspace_tmp_path: Path) -> None:
    config = AuthConfig.for_project(project_name="AstraAuth", environment="test")
    config.save_json(home=workspace_tmp_path, encrypt_values=True)

    diagnostics = runtime_diagnostics_report(home=workspace_tmp_path)

    assert diagnostics.settings_key_exists is True
    assert diagnostics.settings_key_metadata_exists is True
    assert diagnostics.settings_key_id is not None
    assert diagnostics.settings_key_stale is False
    assert diagnostics.config_encrypted is True
    assert "unencrypted_config_values" not in diagnostics.warnings


def test_runtime_diagnostics_warns_for_unencrypted_config(workspace_tmp_path: Path) -> None:
    config = AuthConfig.for_project(project_name="AstraAuth", environment="test")
    config.save_json(home=workspace_tmp_path, encrypt_values=False)

    diagnostics = runtime_diagnostics_report(home=workspace_tmp_path)

    assert diagnostics.config_encrypted is False
    assert "unencrypted_config_values" in diagnostics.warnings


def test_rotate_config_settings_key_preserves_runtime_config(workspace_tmp_path: Path) -> None:
    config = AuthConfig.for_project(
        project_name="AstraAuth",
        environment="test",
        persistence_backend="postgres",
        persistence_password="secret",
        persistence_database="astraauth",
    )
    config.save_json(home=workspace_tmp_path, encrypt_values=True)
    before = runtime_diagnostics_report(home=workspace_tmp_path)

    new_key_id = rotate_config_settings_key(home=workspace_tmp_path)
    after = runtime_diagnostics_report(home=workspace_tmp_path)

    assert new_key_id != before.settings_key_id
    assert after.settings_key_id == new_key_id
    assert (
        load_auth_config(home=workspace_tmp_path).persistence.default_database.password == "secret"
    )


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
