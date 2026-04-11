from __future__ import annotations

import json
from collections.abc import Mapping

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console(markup=False)


def print_text(value: object) -> None:
    console.print(str(value), soft_wrap=True)


def print_json(payload: object) -> None:
    print(json.dumps(payload,indent=4))


def print_kv_lines(pairs: list[tuple[str, object]]) -> None:
    for key, value in pairs:
        print_text(f"{key}={value}")


def print_health_report(payload: Mapping[str, object]) -> None:
    print_kv_lines(
        [
            ("ok", payload["ok"]),
            ("home", payload["home"]),
            ("environment", payload["environment"]),
            ("issuer", payload["issuer"]),
            ("persistence", payload["persistence_backends"]),
            ("oidc_providers", payload["oidc_provider_count"]),
            ("plugins", payload["plugin_count"]),
        ]
    )


def print_persistence(payload: Mapping[str, object]) -> None:
    stores = payload.get("stores", [])
    print_text(f"home={payload['home']}")
    if isinstance(stores, list):
        for store in stores:
            if isinstance(store, dict):
                print_text(
                    f"{store['store_name']}: backend={store['backend']} mode={store['mode']} dsn={store['dsn']}"
                )


def print_schema(payload: Mapping[str, object]) -> None:
    print_text("schema ensured")
    stores = payload.get("stores", [])
    if isinstance(stores, list):
        for store in stores:
            if isinstance(store, dict):
                print_text(f"{store['store_name']}: {store['backend']} -> {store['dsn']}")


def print_runtime_inventory(payload: Mapping[str, object]) -> None:
    print_kv_lines(
        [
            ("home", payload["home"]),
            ("environment", payload["environment"]),
            ("issuer", payload["issuer"]),
            ("oidc_providers", payload["oidc_providers"]),
            ("registered_plugins", payload["registered_plugins"]),
            ("tenant_plugins", payload["tenant_plugins"]),
            ("bootstrap_admin_count", payload["bootstrap_admin_count"]),
        ]
    )


def print_bootstrap(payload: Mapping[str, object]) -> None:
    admins = payload.get("admins", [])
    if not isinstance(admins, list):
        admins = []
    print_text(f"admins={len(admins)}")
    for admin in admins:
        if isinstance(admin, dict):
            print_text(
                f"{admin['tenant_id']}:{admin['username']} role={admin['role_name']} client={admin['client_id']}"
            )


def print_oidc_audit(payload: Mapping[str, object]) -> None:
    records = payload.get("records", [])
    if not isinstance(records, list):
        records = []
    print_text(f"records={len(records)}")
    for record in records:
        if isinstance(record, dict):
            print_text(
                f"{record['created_at']} {record['status']} {record['event_type']} provider={record['provider_id']}"
            )


def print_admin_audit(payload: Mapping[str, object]) -> None:
    records = payload.get("records", [])
    if not isinstance(records, list):
        records = []
    print_text(f"records={len(records)}")
    for record in records:
        if isinstance(record, dict):
            print_text(
                f"{record['created_at']} {record['status']} {record['event_type']} actor={record['actor_username']}"
            )


def print_backup_verification(payload: Mapping[str, object]) -> None:
    print_kv_lines(
        [
            ("artifact_type", payload["artifact_type"]),
            ("path", payload["path"]),
            ("valid", payload["valid"]),
            ("matches_runtime", payload["matches_runtime"]),
            ("details", payload["details"]),
        ]
    )


def print_runtime_diagnostics(payload: Mapping[str, object]) -> None:
    print_kv_lines(
        [
            ("ok", payload["ok"]),
            ("home", payload["home"]),
            ("config_exists", payload["config_exists"]),
            ("config_valid", payload["config_valid"]),
            ("settings_key_exists", payload["settings_key_exists"]),
            ("token_keys_exist", payload["token_keys_exist"]),
            ("token_keys_valid", payload["token_keys_valid"]),
            ("bootstrap_exists", payload["bootstrap_exists"]),
            ("bootstrap_valid", payload["bootstrap_valid"]),
            ("bootstrap_admin_count", payload["bootstrap_admin_count"]),
            ("active_setup_token_count", payload["active_setup_token_count"]),
            ("admin_audit_exists", payload["admin_audit_exists"]),
            ("persistence_backends", payload["persistence_backends"]),
            ("warnings", payload["warnings"]),
            ("issues", payload["issues"]),
            ("details", payload["details"]),
        ]
    )


def print_observability(payload: Mapping[str, object]) -> None:
    print_kv_lines(
        [
            ("home", payload["home"]),
            ("service_name", payload["service_name"]),
            ("correlation_header_name", payload["correlation_header_name"]),
            ("structured_logging_enabled", payload["structured_logging_enabled"]),
            ("metrics_enabled", payload["metrics_enabled"]),
            ("log_path", payload["log_path"]),
            ("metrics_path", payload["metrics_path"]),
            ("counters", payload["counters"]),
        ]
    )


def render_admin_summary(*, home: object, environment: str, issuer: str) -> None:
    panel = Panel.fit(
        f"home={home}\nenvironment={environment}\nissuer={issuer}",
        title="Astra Netra",
    )
    console.print(panel)


def render_action_table(rows: list[tuple[str, str]]) -> None:
    table = Table(title="Available Actions")
    table.add_column("Key")
    table.add_column("Action")
    for key, label in rows:
        table.add_row(key, label)
    console.print(table)
