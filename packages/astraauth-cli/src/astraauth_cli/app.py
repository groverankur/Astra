from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal, TypedDict, cast

import typer

from astraauth.core.config import DEFAULT_ASTRAAUTH_HOME
from astraauth.core.security import SharedThrottleStore, ThrottleStoreSnapshot
from astraauth.core.version import __version__
from astraauth.service import (
    create_bootstrap_setup_token,
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
    list_admin_action_audit_records,
    list_oidc_audit_records,
    list_plugin_audit_records,
    load_bootstrap_manifest,
    lock_bootstrap_setup,
    persistence_report,
    purge_bootstrap_setup_tokens,
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
from astraauth_cli.admin_ui import run_admin_ui
from astraauth_cli.display import (
    print_admin_audit,
    print_backup_verification,
    print_bootstrap,
    print_health_report,
    print_json,
    print_observability,
    print_oidc_audit,
    print_persistence,
    print_runtime_diagnostics,
    print_runtime_inventory,
    print_schema,
    print_security_report,
    print_text,
)
from astraauth_cli.interactive import (
    InteractiveExitError,
    admin_init_answers,
    key_rotate_answers,
    prompt_backend,
    prompt_confirm,
    prompt_environment,
    prompt_text,
    resolve_home,
    select_action,
)
from astraauth_cli.textual_ui import run_textual_admin_ui, run_textual_wizard_ui

app = typer.Typer(
    add_completion=False,
    no_args_is_help=False,
    rich_markup_mode=None,
    help="Astra workspace CLI",
)


class PersistenceStorePayload(TypedDict):
    store_name: str
    backend: str
    mode: str
    dsn: str


class PersistencePayload(TypedDict):
    home: str
    auto_create_schema: bool
    stores: list[PersistenceStorePayload]


class RuntimeInventoryPayload(TypedDict):
    home: str
    environment: str
    issuer: str
    oidc_providers: list[str]
    registered_plugins: list[str]
    tenant_plugins: dict[str, list[str]]
    bootstrap_admin_count: int


def _throttle_snapshot_payload(snapshot: ThrottleStoreSnapshot) -> dict[str, object]:
    buckets = []
    for bucket in snapshot.buckets:
        buckets.append(
            {
                "scope": bucket.scope,
                "fingerprint": bucket.fingerprint,
                "event_count": bucket.event_count,
                "blocked": bucket.blocked,
                "retry_after_seconds": bucket.retry_after_seconds,
            }
        )
    return {
        "storage_kind": snapshot.storage_kind,
        "bucket_count": snapshot.bucket_count,
        "blocked_bucket_count": snapshot.blocked_bucket_count,
        "dsn": snapshot.dsn,
        "table_name": snapshot.table_name,
        "buckets": buckets,
    }


def _runtime_security_payload(home: Path) -> dict[str, object]:
    report = runtime_security_report(home=home)
    diagnostics = runtime_diagnostics_report(home=home)
    admin_ui_snapshot = SharedThrottleStore(str(home / "data" / "admin-ui-throttle.db")).snapshot()
    return {
        "home": str(report.home),
        "config_key_custody": {
            "settings_key_exists": diagnostics.settings_key_exists,
            "settings_key_metadata_exists": diagnostics.settings_key_metadata_exists,
            "settings_key_id": diagnostics.settings_key_id,
            "settings_key_stale": diagnostics.settings_key_stale,
            "config_encrypted": diagnostics.config_encrypted,
            "weak_permission_paths": list(diagnostics.weak_permission_paths),
            "warnings": list(diagnostics.warnings),
        },
        "runtime_throttle": _throttle_snapshot_payload(report.runtime_throttle),
        "admin_ui_throttle": _throttle_snapshot_payload(admin_ui_snapshot),
        "plugin_audit_log_path": str(report.plugin_audit_log_path),
        "plugin_audit_record_count": report.plugin_audit_record_count,
        "recent_plugin_audit_records": [
            {
                "timestamp": record.timestamp.isoformat(),
                "tenant_id": record.tenant_id,
                "plugin_name": record.plugin_name,
                "target": record.target,
                "execution_type": record.execution_type,
                "status": record.status,
                "fail_closed": record.fail_closed,
                "duration_ms": record.duration_ms,
                "error_classification": record.error_classification,
                "message": record.message,
            }
            for record in report.recent_plugin_audit_records
        ],
    }


def _persistence_payload(home: Path) -> PersistencePayload:
    report = persistence_report(home=home)
    return {
        "home": str(report.home),
        "auto_create_schema": report.auto_create_schema,
        "stores": [
            {
                "store_name": store.store_name,
                "backend": store.backend,
                "mode": store.mode,
                "dsn": store.dsn,
            }
            for store in report.stores
        ],
    }


def _schema_payload(home: Path) -> PersistencePayload:
    report = ensure_runtime_schema(home=home)
    return {
        "home": str(report.home),
        "auto_create_schema": report.auto_create_schema,
        "stores": [
            {
                "store_name": store.store_name,
                "backend": store.backend,
                "mode": store.mode,
                "dsn": store.dsn,
            }
            for store in report.stores
        ],
    }


def _runtime_inventory_payload(home: Path) -> RuntimeInventoryPayload:
    report = runtime_inventory_report(home=home)
    return {
        "home": str(report.home),
        "environment": report.environment,
        "issuer": report.issuer,
        "oidc_providers": list(report.oidc_providers),
        "registered_plugins": list(report.registered_plugins),
        "tenant_plugins": {tenant: list(names) for tenant, names in report.tenant_plugins.items()},
        "bootstrap_admin_count": report.bootstrap_admin_count,
    }


@app.callback(invoke_without_command=True)
def root_callback(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        print_text(__version__)


@app.command("version")
def version_command() -> None:
    print_text(__version__)


@app.command("config-home")
def config_home_command() -> None:
    print_text(DEFAULT_ASTRAAUTH_HOME)


@app.command("validate-config")
def validate_config_command(
    home: Annotated[Path, typer.Option("--home")] = DEFAULT_ASTRAAUTH_HOME,
) -> None:
    config = validate_runtime_config(home=home)
    print_text(f"Config OK: environment={config.environment} issuer={config.issuer}")


@app.command("config-init")
def config_init_command(
    home: Annotated[Path, typer.Option("--home")] = DEFAULT_ASTRAAUTH_HOME,
    project_name: Annotated[str, typer.Option("--project-name")] = "Astra",
    environment: Annotated[Literal["dev", "test", "prod"], typer.Option("--environment")] = "dev",
    persistence_backend: Annotated[
        Literal["sqlite", "postgres", "mysql"], typer.Option("--persistence-backend")
    ] = "sqlite",
    persistence_base_dir: Annotated[str | None, typer.Option("--persistence-base-dir")] = None,
    issuer: Annotated[str | None, typer.Option("--issuer")] = None,
    force: Annotated[bool, typer.Option("--force")] = False,
    no_encrypt: Annotated[bool, typer.Option("--no-encrypt")] = False,
) -> None:
    path = initialize_config_home(
        home=home,
        project_name=project_name,
        environment=environment,
        persistence_backend=persistence_backend,
        persistence_base_dir=persistence_base_dir,
        issuer=issuer,
        encrypt_values=not no_encrypt,
        force=force,
    )
    print_text(f"config_path={path}")


@app.command("config-export")
def config_export_command(
    output: Annotated[Path, typer.Option("--output")],
    home: Annotated[Path, typer.Option("--home")] = DEFAULT_ASTRAAUTH_HOME,
) -> None:
    print_text(f"config_export={export_runtime_config(home=home, output_path=output)}")


@app.command("config-import")
def config_import_command(
    input_path: Annotated[Path, typer.Option("--input")],
    home: Annotated[Path, typer.Option("--home")] = DEFAULT_ASTRAAUTH_HOME,
    no_encrypt: Annotated[bool, typer.Option("--no-encrypt")] = False,
) -> None:
    path = import_runtime_config(home=home, input_path=input_path, encrypt_values=not no_encrypt)
    print_text(f"config_import={path}")


@app.command("config-key-rotate")
def config_key_rotate_command(
    home: Annotated[Path, typer.Option("--home")] = DEFAULT_ASTRAAUTH_HOME,
) -> None:
    print_text(f"settings_key_id={rotate_config_settings_key(home=home)}")


@app.command("state-export")
def state_export_command(
    output: Annotated[Path, typer.Option("--output")],
    home: Annotated[Path, typer.Option("--home")] = DEFAULT_ASTRAAUTH_HOME,
    recipient_public_key: Annotated[
        Path | None,
        typer.Option(
            "--recipient-public-key",
            help="PEM RSA public key for portable encrypted bootstrap content in the state bundle.",
        ),
    ] = None,
    unsafe_plaintext_bootstrap: Annotated[
        bool,
        typer.Option(
            "--unsafe-plaintext-bootstrap",
            help="Write bootstrap state inside the bundle as plaintext JSON. Intended only for local debugging.",
        ),
    ] = False,
) -> None:
    print_text(
        "state_export="
        f"{export_runtime_state_bundle(home=home, output_path=output, unsafe_plaintext_bootstrap=unsafe_plaintext_bootstrap, recipient_public_key_path=recipient_public_key)}"
    )


@app.command("state-import")
def state_import_command(
    input_path: Annotated[Path, typer.Option("--input")],
    home: Annotated[Path, typer.Option("--home")] = DEFAULT_ASTRAAUTH_HOME,
    merge_bootstrap: Annotated[bool, typer.Option("--merge-bootstrap")] = False,
    no_encrypt: Annotated[bool, typer.Option("--no-encrypt")] = False,
    recipient_private_key: Annotated[
        Path | None,
        typer.Option(
            "--recipient-private-key",
            help="PEM RSA private key for portable encrypted bootstrap content in the state bundle.",
        ),
    ] = None,
) -> None:
    config_path, bootstrap_path = import_runtime_state_bundle(
        home=home,
        input_path=input_path,
        encrypt_values=not no_encrypt,
        merge_bootstrap=merge_bootstrap,
        recipient_private_key_path=recipient_private_key,
    )
    print_text(f"state_import_config={config_path}")
    print_text(f"state_import_bootstrap={bootstrap_path}")


@app.command("backup-verify")
def backup_verify_command(
    input_path: Annotated[Path, typer.Option("--input")],
    home: Annotated[Path, typer.Option("--home")] = DEFAULT_ASTRAAUTH_HOME,
    as_json: Annotated[bool, typer.Option("--json")] = False,
    recipient_private_key: Annotated[
        Path | None,
        typer.Option(
            "--recipient-private-key",
            help="PEM RSA private key for portable encrypted bootstrap or state-bundle content.",
        ),
    ] = None,
) -> None:
    report = verify_backup_artifact(
        home=home,
        input_path=input_path,
        recipient_private_key_path=recipient_private_key,
    )
    payload = {
        "artifact_type": report.artifact_type,
        "path": str(report.path),
        "valid": report.valid,
        "matches_runtime": report.matches_runtime,
        "details": list(report.details),
    }
    if as_json:
        print_json(payload)
    else:
        print_backup_verification(payload)


@app.command("health")
def health_command(
    home: Annotated[Path, typer.Option("--home")] = DEFAULT_ASTRAAUTH_HOME,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    report = runtime_health_report(home=home)
    payload = {
        "ok": report.ok,
        "home": str(report.home),
        "environment": report.environment,
        "issuer": report.issuer,
        "persistence_backends": report.persistence_backends,
        "oidc_provider_count": report.oidc_provider_count,
        "plugin_count": report.plugin_count,
        "details": list(report.details),
    }
    if as_json:
        print_json(payload)
    else:
        print_health_report(payload)


@app.command("doctor")
def doctor_command(
    home: Annotated[Path, typer.Option("--home")] = DEFAULT_ASTRAAUTH_HOME,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    report = runtime_diagnostics_report(home=home)
    payload = {
        "ok": report.ok,
        "home": str(report.home),
        "config_exists": report.config_exists,
        "config_valid": report.config_valid,
        "settings_key_exists": report.settings_key_exists,
        "settings_key_metadata_exists": report.settings_key_metadata_exists,
        "settings_key_id": report.settings_key_id,
        "settings_key_stale": report.settings_key_stale,
        "weak_permission_paths": list(report.weak_permission_paths),
        "config_encrypted": report.config_encrypted,
        "token_keys_exist": report.token_keys_exist,
        "token_keys_valid": report.token_keys_valid,
        "bootstrap_exists": report.bootstrap_exists,
        "bootstrap_valid": report.bootstrap_valid,
        "bootstrap_admin_count": report.bootstrap_admin_count,
        "active_setup_token_count": report.active_setup_token_count,
        "admin_audit_exists": report.admin_audit_exists,
        "persistence_backends": report.persistence_backends,
        "issues": list(report.issues),
        "warnings": list(report.warnings),
        "details": list(report.details),
    }
    if as_json:
        print_json(payload)
    else:
        print_runtime_diagnostics(payload)


@app.command("observability")
def observability_command(
    home: Annotated[Path, typer.Option("--home")] = DEFAULT_ASTRAAUTH_HOME,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    report = runtime_observability_report(home=home)
    payload = {
        "home": str(report.home),
        "service_name": report.service_name,
        "correlation_header_name": report.correlation_header_name,
        "structured_logging_enabled": report.structured_logging_enabled,
        "metrics_enabled": report.metrics_enabled,
        "log_path": str(report.log_path),
        "metrics_path": str(report.metrics_path),
        "counters": [{"name": counter.name, "value": counter.value} for counter in report.counters],
    }
    if as_json:
        print_json(payload)
    else:
        print_observability(payload)


@app.command("security")
def security_command(
    home: Annotated[Path, typer.Option("--home")] = DEFAULT_ASTRAAUTH_HOME,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    payload = _runtime_security_payload(home)
    if as_json:
        print_json(payload)
    else:
        print_security_report(payload)


@app.command("persistence-info")
def persistence_info_command(
    home: Annotated[Path, typer.Option("--home")] = DEFAULT_ASTRAAUTH_HOME,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    payload = _persistence_payload(home)
    if as_json:
        print_json(payload)
    else:
        print_persistence(payload)


@app.command("schema-ensure")
def schema_ensure_command(
    home: Annotated[Path, typer.Option("--home")] = DEFAULT_ASTRAAUTH_HOME,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    payload = _schema_payload(home)
    if as_json:
        print_json(payload)
    else:
        print_schema(payload)


@app.command("runtime-inventory")
def runtime_inventory_command(
    home: Annotated[Path, typer.Option("--home")] = DEFAULT_ASTRAAUTH_HOME,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    payload = _runtime_inventory_payload(home)
    if as_json:
        print_json(payload)
    else:
        print_runtime_inventory(payload)


@app.command("key-jwks")
def key_jwks_command(
    home: Annotated[Path, typer.Option("--home")] = DEFAULT_ASTRAAUTH_HOME,
) -> None:
    print_json({"keys": export_public_jwks(home=home)})


@app.command("key-export")
def key_export_command(
    output: Annotated[Path, typer.Option("--output")],
    home: Annotated[Path, typer.Option("--home")] = DEFAULT_ASTRAAUTH_HOME,
) -> None:
    print_text(f"key_export={export_token_key_state(home=home, output_path=output)}")


@app.command("key-import")
def key_import_command(
    input_path: Annotated[Path, typer.Option("--input")],
    home: Annotated[Path, typer.Option("--home")] = DEFAULT_ASTRAAUTH_HOME,
) -> None:
    print_text(f"key_import={import_token_key_state(home=home, input_path=input_path)}")


@app.command("key-rotate")
def key_rotate_command(
    use: Annotated[Literal["sig", "enc"], typer.Option("--use")],
    home: Annotated[Path, typer.Option("--home")] = DEFAULT_ASTRAAUTH_HOME,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    persisted_path, keys = rotate_runtime_keys(use=use, home=home)
    payload: dict[str, object] = {"persisted": True, "keys": keys, "path": str(persisted_path)}
    if as_json:
        print_json(payload)
    else:
        print_text(f"persisted={payload['persisted']}")
        print_json({"keys": payload["keys"]})


@app.command("init-admin")
def init_admin_command(
    tenant_id: Annotated[str, typer.Option("--tenant-id")],
    username: Annotated[str, typer.Option("--username")],
    password: Annotated[str, typer.Option("--password", hide_input=True)],
    home: Annotated[Path, typer.Option("--home")] = DEFAULT_ASTRAAUTH_HOME,
    subject_id: Annotated[str | None, typer.Option("--subject-id")] = None,
    role_name: Annotated[str, typer.Option("--role-name")] = "admin",
    client_id: Annotated[str, typer.Option("--client-id")] = "bootstrap-admin-client",
    email: Annotated[str | None, typer.Option("--email")] = None,
) -> None:
    path = write_initial_admin_setup(
        home=home,
        tenant_id=tenant_id,
        username=username,
        password=password,
        subject_id=subject_id,
        role_name=role_name,
        client_id=client_id,
        email=email,
    )
    print_text(f"bootstrap_manifest={path}")


@app.command("bootstrap-token-create")
def bootstrap_token_create_command(
    home: Annotated[Path, typer.Option("--home")] = DEFAULT_ASTRAAUTH_HOME,
    ttl_seconds: Annotated[int, typer.Option("--ttl-seconds")] = 900,
    label: Annotated[str | None, typer.Option("--label")] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    try:
        path, token = create_bootstrap_setup_token(
            home=home,
            ttl_seconds=ttl_seconds,
            label=label,
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise SystemExit(1) from exc
    payload: dict[str, object] = {
        "bootstrap_manifest": str(path),
        "token": token,
        "ttl_seconds": ttl_seconds,
        "label": label,
    }
    if as_json:
        print_json(payload, redact=False)
    else:
        print_text(f"bootstrap_manifest={path}")
        print_text(f"bootstrap_token={token}")


@app.command("bootstrap-token-purge")
def bootstrap_token_purge_command(
    home: Annotated[Path, typer.Option("--home")] = DEFAULT_ASTRAAUTH_HOME,
    remove_all: Annotated[bool, typer.Option("--all")] = False,
) -> None:
    print_text(
        f"bootstrap_manifest={purge_bootstrap_setup_tokens(home=home, remove_all=remove_all)}"
    )


@app.command("bootstrap-lockdown")
def bootstrap_lockdown_command(
    home: Annotated[Path, typer.Option("--home")] = DEFAULT_ASTRAAUTH_HOME,
) -> None:
    print_text(f"bootstrap_manifest={lock_bootstrap_setup(home=home)}")


@app.command("bootstrap-show")
def bootstrap_show_command(
    home: Annotated[Path, typer.Option("--home")] = DEFAULT_ASTRAAUTH_HOME,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    manifest = load_bootstrap_manifest(home=home)
    payload: dict[str, object] = {
        "admins": [
            {
                "subject_id": admin.subject_id,
                "tenant_id": admin.tenant_id,
                "username": admin.username,
                "role_name": admin.role_name,
                "client_id": admin.client_id,
                "email": admin.email,
                "permissions": list(admin.permissions),
                "scopes": list(admin.scopes),
            }
            for admin in manifest.admins
        ],
        "setup_tokens": [
            {
                "token_id": token.token_id,
                "created_at": token.created_at.isoformat(),
                "expires_at": token.expires_at.isoformat(),
                "consumed_at": token.consumed_at.isoformat()
                if token.consumed_at is not None
                else None,
                "label": token.label,
            }
            for token in manifest.setup_tokens
        ],
        "setup_locked": manifest.setup_locked,
    }
    if as_json:
        print_json(payload)
    else:
        print_bootstrap(payload)


@app.command("bootstrap-export")
def bootstrap_export_command(
    output: Annotated[Path, typer.Option("--output")],
    home: Annotated[Path, typer.Option("--home")] = DEFAULT_ASTRAAUTH_HOME,
    recipient_public_key: Annotated[
        Path | None,
        typer.Option(
            "--recipient-public-key",
            help="PEM RSA public key for portable encrypted bootstrap export.",
        ),
    ] = None,
    unsafe_plaintext: Annotated[
        bool,
        typer.Option(
            "--unsafe-plaintext",
            help="Export bootstrap manifest as plaintext JSON. Intended only for local debugging.",
        ),
    ] = False,
) -> None:
    print_text(
        f"bootstrap_export={export_bootstrap_manifest(home=home, output_path=output, unsafe_plaintext=unsafe_plaintext, recipient_public_key_path=recipient_public_key)}"
    )


@app.command("bootstrap-import")
def bootstrap_import_command(
    input_path: Annotated[Path, typer.Option("--input")],
    home: Annotated[Path, typer.Option("--home")] = DEFAULT_ASTRAAUTH_HOME,
    merge: Annotated[bool, typer.Option("--merge")] = False,
    recipient_private_key: Annotated[
        Path | None,
        typer.Option(
            "--recipient-private-key",
            help="PEM RSA private key for portable encrypted bootstrap export.",
        ),
    ] = None,
) -> None:
    print_text(
        "bootstrap_import="
        f"{import_bootstrap_manifest(home=home, input_path=input_path, merge=merge, recipient_private_key_path=recipient_private_key)}"
    )


@app.command("oidc-audit")
def oidc_audit_command(
    tenant_id: Annotated[str, typer.Option("--tenant-id")],
    home: Annotated[Path, typer.Option("--home")] = DEFAULT_ASTRAAUTH_HOME,
    provider_id: Annotated[str | None, typer.Option("--provider-id")] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    payload: dict[str, object] = {
        "records": list(
            list_oidc_audit_records(home=home, tenant_id=tenant_id, provider_id=provider_id)
        )
    }
    if as_json:
        print_json(payload)
    else:
        print_oidc_audit(payload)


@app.command("admin-audit")
def admin_audit_command(
    home: Annotated[Path, typer.Option("--home")] = DEFAULT_ASTRAAUTH_HOME,
    tenant_id: Annotated[str | None, typer.Option("--tenant-id")] = None,
    actor_username: Annotated[str | None, typer.Option("--actor-username")] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    payload: dict[str, object] = {
        "records": list(
            list_admin_action_audit_records(
                home=home,
                tenant_id=tenant_id,
                actor_username=actor_username,
            )
        )
    }
    if as_json:
        print_json(payload)
    else:
        print_admin_audit(payload)


@app.command("plugin-audit")
def plugin_audit_command(
    home: Annotated[Path, typer.Option("--home")] = DEFAULT_ASTRAAUTH_HOME,
    tenant_id: Annotated[str | None, typer.Option("--tenant-id")] = None,
    plugin_name: Annotated[str | None, typer.Option("--plugin-name")] = None,
    execution_type: Annotated[str | None, typer.Option("--execution-type")] = None,
    status: Annotated[str | None, typer.Option("--status")] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    records = list(
        list_plugin_audit_records(
            home=home,
            tenant_id=tenant_id,
            plugin_name=plugin_name,
            execution_type=execution_type,
            status=status,
        )
    )
    payload = {
        "tenant_id": tenant_id,
        "plugin_name": plugin_name,
        "execution_type": execution_type,
        "status": status,
        "records": records,
    }
    if as_json:
        print_json(payload)
    else:
        print_text(f"records={len(records)}")
        for record in records:
            print_text(
                f"{record['timestamp']} {record['status']} {record['plugin_name']} "
                f"{record['execution_type']} target={record['target']} duration_ms={record['duration_ms']}"
            )


@app.command("wizard")
def wizard_command(
    home: Annotated[Path | None, typer.Option("--home")] = None,
    no_tui: Annotated[bool, typer.Option("--no-tui")] = False,
) -> None:
    resolved_home = resolve_home(home)
    if not no_tui and run_textual_wizard_ui(home=resolved_home):
        return
    try:
        action = select_action(
            message="Choose a setup wizard action",
            choices=[
                ("config-init", "Initialize runtime config"),
                ("security", "Inspect security posture"),
                ("init-admin", "Create bootstrap admin"),
                ("key-rotate", "Rotate runtime keys"),
            ],
        )
        if action == "exit":
            print_text("Wizard exited.")
            return
        if action == "config-init":
            project_name = prompt_text("Project name", default="Astra")
            environment = prompt_environment(default="dev")
            backend = prompt_backend(default="sqlite")
            issuer = prompt_text("Issuer", default="https://auth.local")
            force = prompt_confirm("Overwrite existing config if present?", default=False)
            config_init_command(
                home=resolved_home,
                project_name=project_name,
                environment=environment,
                persistence_backend=backend,
                persistence_base_dir=str(resolved_home / "data"),
                issuer=issuer,
                force=force,
                no_encrypt=False,
            )
            return
        if action == "init-admin":
            admin_answers = admin_init_answers(home=resolved_home)
            init_admin_command(
                tenant_id=admin_answers["tenant_id"],
                username=admin_answers["username"],
                password=admin_answers["password"],
                home=resolved_home,
                email=admin_answers["email"],
            )
            return
        if action == "security":
            security_command(home=resolved_home, as_json=False)
            return
        rotate_answers = key_rotate_answers(home=resolved_home)
        key_rotate_command(
            use=cast(Literal["sig", "enc"], rotate_answers["use"]),
            home=resolved_home,
            as_json=False,
        )
    except InteractiveExitError:
        print_text("Wizard exited.")


@app.command("admin-ui")
def admin_ui_command(
    home: Annotated[Path | None, typer.Option("--home")] = None,
    host: Annotated[str, typer.Option("--host")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port")] = 8088,
    tui: Annotated[bool, typer.Option("--tui")] = False,
    no_tui: Annotated[bool, typer.Option("--no-tui")] = False,
) -> None:
    resolved_home = resolve_home(home)
    if tui:
        if run_textual_admin_ui(home=resolved_home):
            return
        no_tui = True

    if no_tui:
        run_admin_ui(
            home=resolved_home,
            init_admin=init_admin_command,
            rotate_keys=key_rotate_command,
            show_health=health_command,
            show_security=security_command,
        )
        return

    try:
        import uvicorn
        from astraauth_admin_ui.app import create_admin_app
    except ImportError:
        typer.echo(
            "Error: Browser admin UI package ('astraauth-admin-ui') or 'uvicorn' is not installed.\n"
            "Please run 'uv sync --all-groups' or install them to use this command.\n"
            "Alternatively, use --tui to launch the terminal interface.",
            err=True,
        )
        raise SystemExit(1) from None

    typer.echo(f"Starting browser admin UI on http://{host}:{port}...")
    uvicorn.run(create_admin_app(home=resolved_home), host=host, port=port)


def main(argv: list[str] | None = None) -> int:
    try:
        app(args=argv, standalone_mode=False)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
        return code
    except typer.Exit as exc:
        return exc.exit_code
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
