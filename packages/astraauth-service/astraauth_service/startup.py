from __future__ import annotations

import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from secrets import token_urlsafe
from typing import Any, cast
from uuid import uuid4

from astraauth_core.authorization.models import Role
from astraauth_core.config import (
    DEFAULT_ASTRAAUTH_HOME,
    AuthConfig,
    StoreName,
    decrypt_runtime_mapping,
    encrypt_runtime_mapping,
)
from astraauth_core.oauth.models import OAuthClient, Subject
from astraauth_core.oauth.password import Sha256PasswordVerifier, hash_password
from astraauth_core.token.token_manager import TokenKeyManager

from astraauth_service.factory import AstraAuthService, build_service
from astraauth_service.observability import (
    ObservabilitySnapshot,
    observability_snapshot,
    record_event,
    record_metric,
)

_BOOTSTRAP_FILENAME = "bootstrap.json"
_TOKEN_KEYS_FILENAME = "token-keys.json"
_STATE_BUNDLE_VERSION = 1
_STORE_NAMES: tuple[StoreName, ...] = ("sessions", "mfa", "plugins", "idp")


@dataclass(frozen=True)
class RuntimeHealthReport:
    ok: bool
    home: Path
    environment: str
    issuer: str
    persistence_backends: dict[str, str]
    oidc_provider_count: int
    plugin_count: int
    details: tuple[str, ...] = ()


@dataclass(frozen=True)
class PersistenceStoreReport:
    store_name: str
    backend: str
    mode: str
    dsn: str


@dataclass(frozen=True)
class PersistenceReport:
    home: Path
    auto_create_schema: bool
    stores: tuple[PersistenceStoreReport, ...]


@dataclass(frozen=True)
class BootstrapAdminRecord:
    subject_id: str
    tenant_id: str
    username: str
    password_hash: str
    role_name: str = "admin"
    client_id: str = "bootstrap-admin-client"
    email: str | None = None
    permissions: tuple[str, ...] = ("openid", "admin:*")
    scopes: tuple[str, ...] = ("openid",)


@dataclass(frozen=True)
class BootstrapSetupTokenRecord:
    token_id: str
    token_hash: str
    created_at: datetime
    expires_at: datetime
    consumed_at: datetime | None = None
    label: str | None = None


@dataclass(frozen=True)
class BootstrapManifest:
    admins: tuple[BootstrapAdminRecord, ...] = ()
    setup_tokens: tuple[BootstrapSetupTokenRecord, ...] = ()
    setup_locked: bool = False


@dataclass(frozen=True)
class RuntimeInventoryReport:
    home: Path
    environment: str
    issuer: str
    oidc_providers: tuple[str, ...]
    registered_plugins: tuple[str, ...]
    tenant_plugins: dict[str, tuple[str, ...]]
    bootstrap_admin_count: int


@dataclass(frozen=True)
class OperatorSetupStatus:
    home: Path
    config_exists: bool
    bootstrap_admin_count: int
    active_setup_token_count: int
    setup_required: bool
    setup_locked: bool = False


@dataclass(frozen=True)
class OperatorAdminPrincipal:
    subject_id: str
    tenant_id: str
    username: str
    roles: tuple[str, ...]


@dataclass(frozen=True)
class AdminActionAuditRecord:
    audit_id: str
    event_type: str
    status: str
    actor_subject_id: str | None
    actor_tenant_id: str | None
    actor_username: str | None
    created_at: datetime
    details: dict[str, Any]


_ADMIN_ACTION_AUDIT_FILENAME = "admin-actions.json"
_BOOTSTRAP_SETUP_TOKEN_TTL_SECONDS = 900


def load_auth_config(*, home: Path | None = None) -> AuthConfig:
    return AuthConfig.load(home=home or DEFAULT_ASTRAAUTH_HOME)


def _token_keys_path(*, home: Path | None = None) -> Path:
    target_home = home or DEFAULT_ASTRAAUTH_HOME
    return target_home / "secrets" / _TOKEN_KEYS_FILENAME


def load_token_key_manager(*, config: AuthConfig, home: Path | None = None) -> TokenKeyManager:
    path = _token_keys_path(home=home)
    if not path.exists():
        manager = TokenKeyManager(config)
        save_token_key_manager(manager, home=home)
        return manager
    raw = json.loads(path.read_text(encoding="utf-8"))
    payload = decrypt_runtime_mapping(raw, home=home)
    if not isinstance(payload, dict):
        raise ValueError("token key state payload must be an object")
    return TokenKeyManager(config, serialized_state=payload)


def save_token_key_manager(manager: TokenKeyManager, *, home: Path | None = None) -> Path:
    path = _token_keys_path(home=home)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = encrypt_runtime_mapping(manager.dump_private_state(), home=home)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def export_token_key_state(*, output_path: Path, home: Path | None = None) -> Path:
    config = load_auth_config(home=home)
    manager = load_token_key_manager(config=config, home=home)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = encrypt_runtime_mapping(manager.dump_private_state(), home=home)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    record_metric(config=config, name="key.exports", home=home)
    record_event(
        config=config,
        event_type="keys.exported",
        status="succeeded",
        home=home,
        details={"output_path": str(output_path)},
    )
    return output_path


def import_token_key_state(*, input_path: Path, config: AuthConfig | None = None, home: Path | None = None) -> Path:
    target_home = home or DEFAULT_ASTRAAUTH_HOME
    runtime_config = config or load_auth_config(home=target_home)
    raw = json.loads(input_path.read_text(encoding="utf-8"))
    payload = decrypt_runtime_mapping(raw, home=target_home)
    if not isinstance(payload, dict):
        raise ValueError("token key state payload must be an object")
    manager = TokenKeyManager(runtime_config, serialized_state=payload)
    path = save_token_key_manager(manager, home=target_home)
    record_metric(config=runtime_config, name="key.imports", home=target_home)
    record_event(
        config=runtime_config,
        event_type="keys.imported",
        status="succeeded",
        home=target_home,
        details={"input_path": str(input_path)},
    )
    return path


def initialize_config_home(
    *,
    project_name: str = "AstraAuth",
    environment: str = "dev",
    persistence_backend: str = "sqlite",
    persistence_base_dir: str | None = None,
    issuer: str | None = None,
    encrypt_values: bool = True,
    force: bool = False,
    home: Path | None = None,
) -> Path:
    target_home = home or DEFAULT_ASTRAAUTH_HOME
    config_path = target_home / "config.json"
    if config_path.exists() and not force:
        raise FileExistsError(f"config already exists at {config_path}")
    config = AuthConfig.for_project(
        project_name=project_name,
        environment=cast(Any, environment),
        persistence_backend=cast(Any, persistence_backend),
        persistence_base_dir=persistence_base_dir or str(target_home / "data"),
        issuer=issuer,
    )
    return config.save_json(home=target_home, encrypt_values=encrypt_values)




def reload_auth_config(
    current: AuthConfig | None = None,
    *,
    home: Path | None = None,
    env: dict[str, str] | None = None,
) -> AuthConfig:
    target_home = home or DEFAULT_ASTRAAUTH_HOME
    if current is None:
        return AuthConfig.load(home=target_home, env=env)
    return current.reload(home=target_home, env=env)


def build_service_from_home(*, home: Path | None = None) -> AstraAuthService:
    target_home = home or DEFAULT_ASTRAAUTH_HOME
    config = load_auth_config(home=target_home)
    token_manager = load_token_key_manager(config=config, home=target_home)
    service = build_service(config=config, token_manager=token_manager, observability_home=target_home)
    apply_bootstrap_manifest(service, home=target_home)
    return service


def refresh_service_from_home(
    *,
    current_config: AuthConfig | None = None,
    home: Path | None = None,
    env: dict[str, str] | None = None,
) -> AstraAuthService:
    target_home = home or DEFAULT_ASTRAAUTH_HOME
    config = reload_auth_config(current_config, home=target_home, env=env)
    token_manager = load_token_key_manager(config=config, home=target_home)
    service = build_service(config=config, token_manager=token_manager, observability_home=target_home)
    apply_bootstrap_manifest(service, home=target_home)
    return service


def bootstrap_service(*, home: Path | None = None) -> AstraAuthService:
    return build_service_from_home(home=home)


def validate_runtime_config(*, home: Path | None = None) -> AuthConfig:
    config = load_auth_config(home=home)
    config.validate()
    return config


def runtime_health_report(*, home: Path | None = None) -> RuntimeHealthReport:
    target_home = home or DEFAULT_ASTRAAUTH_HOME
    config = validate_runtime_config(home=target_home)
    service = build_service(config=config)
    details = [
        f"session_store={type(service.sessions).__name__}",
        f"mfa_store={type(service.mfa_challenges).__name__}",
        f"plugin_runtime={type(service.plugin_runtime).__name__}",
        f"oidc_handler={type(service.oidc_handler).__name__}",
    ]
    persistence_backends = {
        store_name: str(config.persistence.database_for(store_name).backend)
        for store_name in _STORE_NAMES
    }
    return RuntimeHealthReport(
        ok=True,
        home=target_home,
        environment=config.environment,
        issuer=config.issuer,
        persistence_backends=cast(dict[str, str], dict(persistence_backends)),
        oidc_provider_count=len(config.idp.oidc_providers),
        plugin_count=len(service.plugin_runtime.registered_plugin_names()),
        details=tuple(details),
    )


def runtime_inventory_report(*, home: Path | None = None) -> RuntimeInventoryReport:
    target_home = home or DEFAULT_ASTRAAUTH_HOME
    config = validate_runtime_config(home=target_home)
    service = build_service_from_home(home=target_home)
    manifest = load_bootstrap_manifest(home=target_home)
    return RuntimeInventoryReport(
        home=target_home,
        environment=config.environment,
        issuer=config.issuer,
        oidc_providers=tuple(provider.provider_id for provider in config.idp.oidc_providers),
        registered_plugins=service.plugin_runtime.registered_plugin_names(),
        tenant_plugins=service.plugin_runtime.tenant_plugins(),
        bootstrap_admin_count=len(manifest.admins),
    )


def runtime_observability_report(*, home: Path | None = None) -> ObservabilitySnapshot:
    target_home = home or DEFAULT_ASTRAAUTH_HOME
    config = validate_runtime_config(home=target_home)
    return observability_snapshot(config=config, home=target_home)


def persistence_report(*, home: Path | None = None) -> PersistenceReport:
    target_home = home or DEFAULT_ASTRAAUTH_HOME
    config = validate_runtime_config(home=target_home)
    stores = tuple(
        PersistenceStoreReport(
        store_name=store_name,
        backend=str(config.persistence.database_for(store_name).backend),
        mode=str(config.persistence.database_for(store_name).mode),
        dsn=config.persistence.dsn_for(store_name, mode="sync"),
    )
        for store_name in _STORE_NAMES
    )
    return PersistenceReport(
        home=target_home,
        auto_create_schema=config.persistence.auto_create_schema,
        stores=stores,
    )


def ensure_runtime_schema(*, home: Path | None = None) -> PersistenceReport:
    target_home = home or DEFAULT_ASTRAAUTH_HOME
    _ = build_service_from_home(home=target_home)
    return persistence_report(home=target_home)


def _bootstrap_payload(manifest: BootstrapManifest) -> dict[str, Any]:
    return {
        "setup_locked": manifest.setup_locked,
        "admins": [
            {
                "subject_id": admin.subject_id,
                "tenant_id": admin.tenant_id,
                "username": admin.username,
                "password_hash": admin.password_hash,
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
                "token_hash": token.token_hash,
                "created_at": token.created_at.isoformat(),
                "expires_at": token.expires_at.isoformat(),
                "consumed_at": token.consumed_at.isoformat() if token.consumed_at is not None else None,
                "label": token.label,
            }
            for token in manifest.setup_tokens
        ],
    }


def _bootstrap_manifest_from_payload(payload: Any) -> BootstrapManifest:
    if not isinstance(payload, dict):
        raise ValueError("bootstrap payload must be an object")
    raw_admins = payload.get("admins", [])
    if not isinstance(raw_admins, list):
        raise ValueError("bootstrap admins must be a list")
    admins: list[BootstrapAdminRecord] = []
    for item in raw_admins:
        if not isinstance(item, dict):
            raise ValueError("bootstrap admin entry must be an object")
        admins.append(
            BootstrapAdminRecord(
                subject_id=str(item["subject_id"]),
                tenant_id=str(item["tenant_id"]),
                username=str(item["username"]),
                password_hash=_bootstrap_password_hash_from_payload(item),
                role_name=str(item.get("role_name", "admin")),
                client_id=str(item.get("client_id", "bootstrap-admin-client")),
                email=str(item["email"]) if item.get("email") is not None else None,
                permissions=tuple(
                    str(value) for value in item.get("permissions", ("openid", "admin:*"))
                ),
                scopes=tuple(str(value) for value in item.get("scopes", ("openid",))),
            )
        )
    raw_tokens = payload.get("setup_tokens", [])
    if not isinstance(raw_tokens, list):
        raise ValueError("bootstrap setup tokens must be a list")
    tokens: list[BootstrapSetupTokenRecord] = []
    for item in raw_tokens:
        if not isinstance(item, dict):
            raise ValueError("bootstrap setup token entry must be an object")
        tokens.append(
            BootstrapSetupTokenRecord(
                token_id=str(item["token_id"]),
                token_hash=str(item["token_hash"]),
                created_at=datetime.fromisoformat(str(item["created_at"])).replace(tzinfo=UTC),
                expires_at=datetime.fromisoformat(str(item["expires_at"])).replace(tzinfo=UTC),
                consumed_at=(
                    datetime.fromisoformat(str(item["consumed_at"])).replace(tzinfo=UTC)
                    if item.get("consumed_at") is not None
                    else None
                ),
                label=str(item["label"]) if item.get("label") is not None else None,
            )
        )
    setup_locked = bool(payload.get("setup_locked", False))
    return BootstrapManifest(admins=tuple(admins), setup_tokens=tuple(tokens), setup_locked=setup_locked)


def load_bootstrap_manifest(*, home: Path | None = None) -> BootstrapManifest:
    target_home = home or DEFAULT_ASTRAAUTH_HOME
    path = target_home / _BOOTSTRAP_FILENAME
    if not path.exists():
        return BootstrapManifest()
    return _bootstrap_manifest_from_payload(json.loads(path.read_text(encoding="utf-8")))


def operator_setup_status(*, home: Path | None = None) -> OperatorSetupStatus:
    target_home = home or DEFAULT_ASTRAAUTH_HOME
    manifest = load_bootstrap_manifest(home=target_home)
    config_exists = (target_home / "config.json").exists()
    now = datetime.now(tz=UTC)
    active_setup_token_count = sum(
        1
        for token in manifest.setup_tokens
        if token.consumed_at is None and token.expires_at >= now
    )
    return OperatorSetupStatus(
        home=target_home,
        config_exists=config_exists,
        bootstrap_admin_count=len(manifest.admins),
        active_setup_token_count=active_setup_token_count,
        setup_required=len(manifest.admins) == 0,
        setup_locked=manifest.setup_locked,
    )


def authenticate_operator_admin(
    *,
    tenant_id: str,
    username: str,
    password: str,
    home: Path | None = None,
) -> OperatorAdminPrincipal:
    target_home = home or DEFAULT_ASTRAAUTH_HOME
    if (target_home / "config.json").exists():
        service = build_service_from_home(home=target_home)
        subject = service.password_authenticator.authenticate(
            username=username,
            password=password,
            tenant_id=tenant_id,
        )
        if subject is None:
            raise ValueError("invalid_admin_credentials")
        assignment = service.assignments.get_assignments(subject.subject_id, tenant_id)
        roles = tuple(sorted(assignment.roles)) if assignment is not None else ()
        if not _roles_have_admin_access(service=service, tenant_id=tenant_id, roles=roles, home=target_home):
            raise PermissionError("admin_access_required")
        return OperatorAdminPrincipal(
            subject_id=subject.subject_id,
            tenant_id=tenant_id,
            username=username,
            roles=roles,
        )

    for admin in load_bootstrap_manifest(home=target_home).admins:
        if admin.tenant_id != tenant_id or admin.username != username:
            continue
        if not Sha256PasswordVerifier().verify(
            provided_password=password,
            stored_password_hash=admin.password_hash,
        ):
            raise ValueError("invalid_admin_credentials")
        if not _bootstrap_record_has_admin_access(admin):
            raise PermissionError("admin_access_required")
        return OperatorAdminPrincipal(
            subject_id=admin.subject_id,
            tenant_id=admin.tenant_id,
            username=admin.username,
            roles=(admin.role_name,),
        )
    raise ValueError("invalid_admin_credentials")


def list_oidc_audit_records(
    *,
    tenant_id: str,
    provider_id: str | None = None,
    home: Path | None = None,
) -> tuple[dict[str, Any], ...]:
    service = build_service_from_home(home=home)
    records = service.list_oidc_audit_records(tenant_id=tenant_id, provider_id=provider_id)
    return tuple(
        {
            "audit_id": record.audit_id,
            "event_type": record.event_type,
            "provider_id": record.provider_id,
            "tenant_id": record.tenant_id,
            "status": record.status,
            "created_at": record.created_at.isoformat(),
            "state_id": record.state_id,
            "client_id": record.client_id,
            "subject_id": record.subject_id,
            "external_subject": record.external_subject,
            "reason": record.reason,
            "details": dict(record.details),
        }
        for record in records
    )


def list_admin_action_audit_records(
    *,
    home: Path | None = None,
    tenant_id: str | None = None,
    actor_username: str | None = None,
) -> tuple[dict[str, Any], ...]:
    records = _load_admin_action_audit_records(home=home)
    return tuple(
        {
            "audit_id": record.audit_id,
            "event_type": record.event_type,
            "status": record.status,
            "actor_subject_id": record.actor_subject_id,
            "actor_tenant_id": record.actor_tenant_id,
            "actor_username": record.actor_username,
            "created_at": record.created_at.isoformat(),
            "details": dict(record.details),
        }
        for record in records
        if (tenant_id is None or record.actor_tenant_id == tenant_id)
        and (actor_username is None or record.actor_username == actor_username)
    )


def record_admin_action(
    *,
    event_type: str,
    status: str,
    details: dict[str, Any] | None = None,
    actor: OperatorAdminPrincipal | None = None,
    home: Path | None = None,
) -> Path:
    target_home = home or DEFAULT_ASTRAAUTH_HOME
    config = load_auth_config(home=target_home) if (target_home / "config.json").exists() else AuthConfig()
    records = list(_load_admin_action_audit_records(home=target_home))
    records.append(
        AdminActionAuditRecord(
            audit_id=str(uuid4()),
            event_type=event_type,
            status=status,
            actor_subject_id=actor.subject_id if actor is not None else None,
            actor_tenant_id=actor.tenant_id if actor is not None else None,
            actor_username=actor.username if actor is not None else None,
            created_at=datetime.now(tz=UTC),
            details=details or {},
        )
    )
    path = _save_admin_action_audit_records(tuple(records), home=target_home)
    record_event(
        config=config,
        event_type=event_type,
        status=status,
        home=target_home,
        details=details or {},
        level="WARNING" if status != "succeeded" else "INFO",
    )
    return path


def export_runtime_config(
    *,
    output_path: Path,
    home: Path | None = None,
) -> Path:
    config = load_auth_config(home=home)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(config.model_dump(mode="json"), indent=2), encoding="utf-8")
    return output_path


def import_runtime_config(
    *,
    input_path: Path,
    home: Path | None = None,
    encrypt_values: bool = True,
) -> Path:
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    config = AuthConfig.model_validate(payload)
    return config.save_json(home=home or DEFAULT_ASTRAAUTH_HOME, encrypt_values=encrypt_values)


def export_bootstrap_manifest(*, output_path: Path, home: Path | None = None) -> Path:
    manifest = load_bootstrap_manifest(home=home)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(_bootstrap_payload(manifest), indent=2), encoding="utf-8")
    return output_path


def create_bootstrap_setup_token(
    *,
    home: Path | None = None,
    ttl_seconds: int = _BOOTSTRAP_SETUP_TOKEN_TTL_SECONDS,
    label: str | None = None,
) -> tuple[Path, str]:
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")
    target_home = home or DEFAULT_ASTRAAUTH_HOME
    manifest = load_bootstrap_manifest(home=target_home)
    if manifest.setup_locked:
        raise ValueError("bootstrap_setup_locked")
    plain_token = token_urlsafe(24)
    now = datetime.now(tz=UTC)
    record = BootstrapSetupTokenRecord(
        token_id=str(uuid4()),
        token_hash=hash_password(plain_token),
        created_at=now,
        expires_at=now + timedelta(seconds=ttl_seconds),
        consumed_at=None,
        label=label,
    )
    path = save_bootstrap_manifest(
        BootstrapManifest(
            admins=manifest.admins,
            setup_tokens=(*manifest.setup_tokens, record),
            setup_locked=manifest.setup_locked,
        ),
        home=target_home,
    )
    return path, plain_token


def verify_bootstrap_setup_token(
    *,
    token: str,
    home: Path | None = None,
) -> BootstrapSetupTokenRecord:
    target_home = home or DEFAULT_ASTRAAUTH_HOME
    manifest = load_bootstrap_manifest(home=target_home)
    now = datetime.now(tz=UTC)
    for record in manifest.setup_tokens:
        if record.consumed_at is not None:
            continue
        if record.expires_at < now:
            continue
        if hmac.compare_digest(record.token_hash, hash_password(token)):
            return record
    raise ValueError("invalid_bootstrap_setup_token")


def consume_bootstrap_setup_token(
    *,
    token: str,
    home: Path | None = None,
) -> Path:
    target_home = home or DEFAULT_ASTRAAUTH_HOME
    manifest = load_bootstrap_manifest(home=target_home)
    matched = verify_bootstrap_setup_token(token=token, home=target_home)
    now = datetime.now(tz=UTC)
    updated_tokens = tuple(
        BootstrapSetupTokenRecord(
            token_id=record.token_id,
            token_hash=record.token_hash,
            created_at=record.created_at,
            expires_at=record.expires_at,
            consumed_at=now if record.token_id == matched.token_id else record.consumed_at,
            label=record.label,
        )
        for record in manifest.setup_tokens
    )
    return save_bootstrap_manifest(
        BootstrapManifest(
            admins=manifest.admins,
            setup_tokens=updated_tokens,
            setup_locked=manifest.setup_locked,
        ),
        home=target_home,
    )


def purge_bootstrap_setup_tokens(
    *,
    home: Path | None = None,
    remove_all: bool = False,
) -> Path:
    target_home = home or DEFAULT_ASTRAAUTH_HOME
    manifest = load_bootstrap_manifest(home=target_home)
    now = datetime.now(tz=UTC)
    remaining_tokens = tuple(
        token
        for token in manifest.setup_tokens
        if not remove_all and token.consumed_at is None and token.expires_at >= now
    )
    return save_bootstrap_manifest(
        BootstrapManifest(
            admins=manifest.admins,
            setup_tokens=remaining_tokens,
            setup_locked=manifest.setup_locked,
        ),
        home=target_home,
    )


def lock_bootstrap_setup(*, home: Path | None = None) -> Path:
    target_home = home or DEFAULT_ASTRAAUTH_HOME
    manifest = load_bootstrap_manifest(home=target_home)
    return save_bootstrap_manifest(
        BootstrapManifest(
            admins=manifest.admins,
            setup_tokens=(),
            setup_locked=True,
        ),
        home=target_home,
    )


def import_bootstrap_manifest(
    *,
    input_path: Path,
    home: Path | None = None,
    merge: bool = False,
) -> Path:
    imported = _bootstrap_manifest_from_payload(json.loads(input_path.read_text(encoding="utf-8")))
    if not merge:
        return save_bootstrap_manifest(imported, home=home)
    existing = load_bootstrap_manifest(home=home)
    merged: dict[tuple[str, str], BootstrapAdminRecord] = {
        (admin.tenant_id, admin.username): admin for admin in existing.admins
    }
    for admin in imported.admins:
        merged[(admin.tenant_id, admin.username)] = admin
    return save_bootstrap_manifest(
        BootstrapManifest(
            admins=tuple(merged.values()),
            setup_tokens=(*existing.setup_tokens, *imported.setup_tokens),
        ),
        home=home,
    )


def export_runtime_state_bundle(
    *,
    output_path: Path,
    home: Path | None = None,
) -> Path:
    config = load_auth_config(home=home)
    manifest = load_bootstrap_manifest(home=home)
    payload = {
        "bundle_version": _STATE_BUNDLE_VERSION,
        "config": config.model_dump(mode="json"),
        "bootstrap": _bootstrap_payload(manifest),
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return output_path


def import_runtime_state_bundle(
    *,
    input_path: Path,
    home: Path | None = None,
    encrypt_values: bool = True,
    merge_bootstrap: bool = False,
) -> tuple[Path, Path]:
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("runtime state bundle must be an object")
    if int(payload.get("bundle_version", 0)) != _STATE_BUNDLE_VERSION:
        raise ValueError("unsupported runtime state bundle version")
    config_payload = payload.get("config")
    bootstrap_payload = payload.get("bootstrap")
    if not isinstance(config_payload, dict):
        raise ValueError("runtime state bundle config must be an object")
    if not isinstance(bootstrap_payload, dict):
        raise ValueError("runtime state bundle bootstrap must be an object")

    target_home = home or DEFAULT_ASTRAAUTH_HOME
    config = AuthConfig.model_validate(config_payload)
    config_path = config.save_json(
        home=target_home,
        encrypt_values=encrypt_values,
    )
    imported_manifest = _bootstrap_manifest_from_payload(bootstrap_payload)
    if merge_bootstrap:
        existing = load_bootstrap_manifest(home=target_home)
        merged: dict[tuple[str, str], BootstrapAdminRecord] = {
            (admin.tenant_id, admin.username): admin for admin in existing.admins
        }
        for admin in imported_manifest.admins:
            merged[(admin.tenant_id, admin.username)] = admin
        bootstrap_path = save_bootstrap_manifest(
            BootstrapManifest(
                admins=tuple(merged.values()),
                setup_tokens=(*existing.setup_tokens, *imported_manifest.setup_tokens),
                setup_locked=existing.setup_locked or imported_manifest.setup_locked,
            ),
            home=target_home,
        )
    else:
        bootstrap_path = save_bootstrap_manifest(imported_manifest, home=target_home)
    return config_path, bootstrap_path


def save_bootstrap_manifest(manifest: BootstrapManifest, *, home: Path | None = None) -> Path:
    target_home = home or DEFAULT_ASTRAAUTH_HOME
    target_home.mkdir(parents=True, exist_ok=True)
    payload = _bootstrap_payload(manifest)
    path = target_home / _BOOTSTRAP_FILENAME
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def write_initial_admin_setup(
    *,
    username: str,
    password: str,
    tenant_id: str,
    home: Path | None = None,
    subject_id: str | None = None,
    role_name: str = "admin",
    client_id: str = "bootstrap-admin-client",
    email: str | None = None,
    permissions: tuple[str, ...] = ("openid", "admin:*"),
    scopes: tuple[str, ...] = ("openid",),
) -> Path:
    target_home = home or DEFAULT_ASTRAAUTH_HOME
    manifest = load_bootstrap_manifest(home=target_home)
    record = BootstrapAdminRecord(
        subject_id=subject_id or f"local:{tenant_id}:{username}",
        tenant_id=tenant_id,
        username=username,
        password_hash=hash_password(password),
        role_name=role_name,
        client_id=client_id,
        email=email,
        permissions=permissions,
        scopes=scopes,
    )
    remaining = [
        admin
        for admin in manifest.admins
        if not (admin.tenant_id == record.tenant_id and admin.username == record.username)
    ]
    return save_bootstrap_manifest(
        BootstrapManifest(
            admins=(*remaining, record),
            setup_tokens=(),
            setup_locked=manifest.setup_locked,
        ),
        home=target_home,
    )


def apply_bootstrap_manifest(service: AstraAuthService, *, home: Path | None = None) -> None:
    manifest = load_bootstrap_manifest(home=home)
    for admin in manifest.admins:
        service.add_role(Role(name=admin.role_name, permissions=set(admin.permissions)))
        service.add_client(
            OAuthClient(
                client_id=admin.client_id,
                redirect_uris=set(),
                allowed_scopes=set(admin.scopes),
                allowed_tenants={admin.tenant_id},
                client_type="public",
                auth_method="none",
                require_pkce=False,
            )
        )
        service.add_subject_password_hash(
            subject=Subject(
                subject_id=admin.subject_id,
                tenants={admin.tenant_id},
                username=admin.username,
                email=admin.email,
            ),
            tenant_id=admin.tenant_id,
            username=admin.username,
            password_hash=admin.password_hash,
        )
        service.assign_roles(
            subject_id=admin.subject_id,
            tenant_id=admin.tenant_id,
            roles={admin.role_name},
        )


def export_public_jwks(*, home: Path | None = None) -> list[dict[str, Any]]:
    return build_service_from_home(home=home).token_manager.get_jwks()


def rotate_runtime_keys(*, use: str, home: Path | None = None) -> tuple[Path, list[dict[str, Any]]]:
    service = build_service_from_home(home=home)
    service.token_manager.rotate_keys(use=use)
    path = save_token_key_manager(service.token_manager, home=home)
    config = load_auth_config(home=home)
    record_metric(config=config, name="key.rotations", home=home)
    record_event(
        config=config,
        event_type="keys.rotated",
        status="succeeded",
        home=home,
        details={"use": use},
    )
    return path, service.token_manager.get_jwks()


def _bootstrap_record_has_admin_access(record: BootstrapAdminRecord) -> bool:
    return record.role_name.lower() in {"admin", "superadmin", "ops-admin"} or any(
        permission == "admin:*" or permission.startswith("admin:")
        for permission in record.permissions
    )


def _bootstrap_password_hash_from_payload(item: dict[str, Any]) -> str:
    if item.get("password_hash") is not None:
        return str(item["password_hash"])
    if item.get("password") is not None:
        return hash_password(str(item["password"]))
    raise ValueError("bootstrap admin entry must contain password_hash")


def _roles_have_admin_access(
    *,
    service: AstraAuthService,
    tenant_id: str,
    roles: tuple[str, ...],
    home: Path | None = None,
) -> bool:
    for role_name in roles:
        role = service.roles.get_role(role_name)
        if role is None:
            continue
        if role.name.lower() in {"admin", "superadmin", "ops-admin"}:
            return True
        if "admin:*" in role.permissions or any(
            permission.startswith("admin:") for permission in role.permissions
        ):
            return True
    manifest = load_bootstrap_manifest(home=home)
    return any(
        admin.tenant_id == tenant_id
        and admin.role_name in roles
        and _bootstrap_record_has_admin_access(admin)
        for admin in manifest.admins
    )


def _admin_action_audit_path(*, home: Path | None = None) -> Path:
    target_home = home or DEFAULT_ASTRAAUTH_HOME
    return target_home / _ADMIN_ACTION_AUDIT_FILENAME


def _save_admin_action_audit_records(
    records: tuple[AdminActionAuditRecord, ...],
    *,
    home: Path | None = None,
) -> Path:
    target_home = home or DEFAULT_ASTRAAUTH_HOME
    path = _admin_action_audit_path(home=target_home)
    target_home.mkdir(parents=True, exist_ok=True)
    payload = encrypt_runtime_mapping(
        {
            "records": [
                {
                    "audit_id": record.audit_id,
                    "event_type": record.event_type,
                    "status": record.status,
                    "actor_subject_id": record.actor_subject_id,
                    "actor_tenant_id": record.actor_tenant_id,
                    "actor_username": record.actor_username,
                    "created_at": record.created_at.isoformat(),
                    "details": dict(record.details),
                }
                for record in records
            ]
        },
        home=target_home,
    )
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def _load_admin_action_audit_records(*, home: Path | None = None) -> tuple[AdminActionAuditRecord, ...]:
    path = _admin_action_audit_path(home=home)
    if not path.exists():
        return ()
    raw = json.loads(path.read_text(encoding="utf-8"))
    payload = decrypt_runtime_mapping(raw, home=path.parent)
    if not isinstance(payload, dict):
        raise ValueError("admin action audit payload must be an object")
    raw_records = payload.get("records", [])
    if not isinstance(raw_records, list):
        raise ValueError("admin action audit records must be a list")
    return tuple(
        AdminActionAuditRecord(
            audit_id=str(item["audit_id"]),
            event_type=str(item["event_type"]),
            status=str(item["status"]),
            actor_subject_id=str(item["actor_subject_id"]) if item.get("actor_subject_id") is not None else None,
            actor_tenant_id=str(item["actor_tenant_id"]) if item.get("actor_tenant_id") is not None else None,
            actor_username=str(item["actor_username"]) if item.get("actor_username") is not None else None,
            created_at=datetime.fromisoformat(str(item["created_at"])).replace(tzinfo=UTC),
            details=dict(item.get("details", {})),
        )
        for item in raw_records
        if isinstance(item, dict)
    )



@dataclass(frozen=True)
class BackupVerificationReport:
    artifact_type: str
    path: Path
    valid: bool
    matches_runtime: bool | None
    details: tuple[str, ...] = ()


@dataclass(frozen=True)
class RuntimeDiagnosticsReport:
    home: Path
    ok: bool
    config_exists: bool
    config_valid: bool
    settings_key_exists: bool
    token_keys_exist: bool
    token_keys_valid: bool
    bootstrap_exists: bool
    bootstrap_valid: bool
    bootstrap_admin_count: int
    active_setup_token_count: int
    admin_audit_exists: bool
    persistence_backends: dict[str, str]
    issues: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    details: tuple[str, ...] = ()


def verify_backup_artifact(
    *,
    input_path: Path,
    home: Path | None = None,
) -> BackupVerificationReport:
    target_home = home or DEFAULT_ASTRAAUTH_HOME
    raw = json.loads(input_path.read_text(encoding="utf-8"))
    details: list[str] = []

    if isinstance(raw, dict) and raw.get("bundle_version") == _STATE_BUNDLE_VERSION:
        config_payload = raw.get("config")
        bootstrap_payload = raw.get("bootstrap")
        if not isinstance(config_payload, dict) or not isinstance(bootstrap_payload, dict):
            return BackupVerificationReport(
                artifact_type="state_bundle",
                path=input_path,
                valid=False,
                matches_runtime=None,
                details=("invalid_state_bundle_payload",),
            )
        config = AuthConfig.model_validate(config_payload)
        manifest = _bootstrap_manifest_from_payload(bootstrap_payload)
        matches_runtime = False
        if (target_home / 'config.json').exists():
            current_config = load_auth_config(home=target_home)
            current_manifest = load_bootstrap_manifest(home=target_home)
            matches_runtime = (
                current_config.model_dump(mode="json") == config.model_dump(mode="json")
                and _bootstrap_payload(current_manifest) == _bootstrap_payload(manifest)
            )
        details.append(f"issuer={config.issuer}")
        details.append(f"bootstrap_admins={len(manifest.admins)}")
        return BackupVerificationReport(
            artifact_type="state_bundle",
            path=input_path,
            valid=True,
            matches_runtime=matches_runtime,
            details=tuple(details),
        )

    if isinstance(raw, dict) and isinstance(raw.get("admins"), list):
        manifest = _bootstrap_manifest_from_payload(raw)
        bootstrap_matches_runtime: bool | None = None
        if (target_home / _BOOTSTRAP_FILENAME).exists():
            bootstrap_matches_runtime = (
                _bootstrap_payload(load_bootstrap_manifest(home=target_home)) == _bootstrap_payload(manifest)
            )
        details.append(f"bootstrap_admins={len(manifest.admins)}")
        details.append(f"setup_tokens={len(manifest.setup_tokens)}")
        return BackupVerificationReport(
            artifact_type="bootstrap",
            path=input_path,
            valid=True,
            matches_runtime=bootstrap_matches_runtime,
            details=tuple(details),
        )

    try:
        config = load_auth_config(home=target_home)
        payload = decrypt_runtime_mapping(raw, home=target_home)
        if not isinstance(payload, dict):
            raise ValueError("token key state payload must be an object")
        manager = TokenKeyManager(config, serialized_state=payload)
        current_manager = load_token_key_manager(config=config, home=target_home)
        matches_runtime = current_manager.dump_private_state() == manager.dump_private_state()
        details.append(f"keys={len(manager.get_jwks())}")
        return BackupVerificationReport(
            artifact_type="token_keys",
            path=input_path,
            valid=True,
            matches_runtime=matches_runtime,
            details=tuple(details),
        )
    except Exception:
        pass

    try:
        config = AuthConfig.model_validate(raw)
        config_matches_runtime: bool | None = None
        if (target_home / 'config.json').exists():
            config_matches_runtime = (
                load_auth_config(home=target_home).model_dump(mode="json") == config.model_dump(mode="json")
            )
        details.append(f"environment={config.environment}")
        details.append(f"issuer={config.issuer}")
        return BackupVerificationReport(
            artifact_type="config",
            path=input_path,
            valid=True,
            matches_runtime=config_matches_runtime,
            details=tuple(details),
        )
    except Exception as exc:
        return BackupVerificationReport(
            artifact_type="unknown",
            path=input_path,
            valid=False,
            matches_runtime=None,
            details=(f"verification_failed={exc}",),
        )



def _inspect_config_and_keys(
    *,
    target_home: Path,
) -> tuple[bool, bool, dict[str, str], list[str], list[str], list[str]]:
    config_path = target_home / "config.json"
    issues: list[str] = []
    warnings: list[str] = []
    details: list[str] = []
    persistence_backends: dict[str, str] = {}
    config_valid = False
    token_keys_valid = False

    if not config_path.exists():
        issues.append("missing_config")
        return config_valid, token_keys_valid, persistence_backends, issues, warnings, details

    try:
        config = load_auth_config(home=target_home)
        config.validate()
        config_valid = True
        persistence_backends = {
            store_name: str(config.persistence.database_for(store_name).backend)
            for store_name in _STORE_NAMES
        }
        details.append(f"environment={config.environment}")
        details.append(f"issuer={config.issuer}")
    except Exception as exc:
        issues.append(f"invalid_config:{exc}")
        return config_valid, token_keys_valid, persistence_backends, issues, warnings, details

    try:
        manager = load_token_key_manager(config=config, home=target_home)
        token_keys_valid = True
        details.append(f"jwks_keys={len(manager.get_jwks())}")
    except Exception as exc:
        issues.append(f"invalid_token_keys:{exc}")

    return config_valid, token_keys_valid, persistence_backends, issues, warnings, details


def _inspect_bootstrap_and_audit(
    *,
    target_home: Path,
) -> tuple[bool, int, int, bool, list[str], list[str], list[str]]:
    bootstrap_path = target_home / _BOOTSTRAP_FILENAME
    admin_audit_path = _admin_action_audit_path(home=target_home)
    issues: list[str] = []
    warnings: list[str] = []
    details: list[str] = []
    bootstrap_valid = False
    bootstrap_admin_count = 0
    active_setup_token_count = 0

    if bootstrap_path.exists():
        try:
            manifest = load_bootstrap_manifest(home=target_home)
            bootstrap_valid = True
            bootstrap_admin_count = len(manifest.admins)
            now = datetime.now(tz=UTC)
            active_setup_token_count = sum(
                1
                for token in manifest.setup_tokens
                if token.consumed_at is None and token.expires_at >= now
            )
            if bootstrap_admin_count > 0:
                warnings.append("bootstrap_manifest_present")
                if not manifest.setup_locked:
                    warnings.append("bootstrap_setup_not_locked")
            if active_setup_token_count > 0:
                warnings.append("active_setup_tokens_present")
        except Exception as exc:
            issues.append(f"invalid_bootstrap_manifest:{exc}")
    else:
        details.append("bootstrap_manifest=absent")

    if admin_audit_path.exists():
        try:
            records = _load_admin_action_audit_records(home=target_home)
            details.append(f"admin_audit_records={len(records)}")
        except Exception as exc:
            issues.append(f"invalid_admin_audit:{exc}")

    return (
        bootstrap_valid,
        bootstrap_admin_count,
        active_setup_token_count,
        admin_audit_path.exists(),
        issues,
        warnings,
        details,
    )
def runtime_diagnostics_report(*, home: Path | None = None) -> RuntimeDiagnosticsReport:
    target_home = home or DEFAULT_ASTRAAUTH_HOME
    config_path = target_home / "config.json"
    settings_key_path = target_home / "secrets" / "settings.key"
    token_keys_path = _token_keys_path(home=target_home)
    bootstrap_path = target_home / _BOOTSTRAP_FILENAME

    (
        config_valid,
        token_keys_valid,
        persistence_backends,
        config_issues,
        config_warnings,
        config_details,
    ) = _inspect_config_and_keys(target_home=target_home)
    (
        bootstrap_valid,
        bootstrap_admin_count,
        active_setup_token_count,
        admin_audit_exists,
        bootstrap_issues,
        bootstrap_warnings,
        bootstrap_details,
    ) = _inspect_bootstrap_and_audit(target_home=target_home)

    issues = [*config_issues, *bootstrap_issues]
    warnings = [*config_warnings, *bootstrap_warnings]
    details = [*config_details, *bootstrap_details]

    if not settings_key_path.exists():
        warnings.append("missing_settings_key")
    if not token_keys_path.exists():
        warnings.append("missing_token_keys")

    return RuntimeDiagnosticsReport(
        home=target_home,
        ok=not issues,
        config_exists=config_path.exists(),
        config_valid=config_valid,
        settings_key_exists=settings_key_path.exists(),
        token_keys_exist=token_keys_path.exists(),
        token_keys_valid=token_keys_valid,
        bootstrap_exists=bootstrap_path.exists(),
        bootstrap_valid=bootstrap_valid,
        bootstrap_admin_count=bootstrap_admin_count,
        active_setup_token_count=active_setup_token_count,
        admin_audit_exists=admin_audit_exists,
        persistence_backends=persistence_backends,
        issues=tuple(issues),
        warnings=tuple(warnings),
        details=tuple(details),
    )

