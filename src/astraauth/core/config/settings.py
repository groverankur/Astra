from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import quote, urlencode
from uuid import uuid4

from cryptography.fernet import Fernet, InvalidToken
from glom import PathAccessError, assign, glom
from pydantic import BaseModel, ConfigDict, Field, model_validator
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    EnvSettingsSource,
    SettingsConfigDict,
)

EnvironmentName = Literal["dev", "test", "prod"]
DatabaseBackend = Literal["sqlite", "postgres", "mysql"]
DatabaseMode = Literal["sync", "async"]
StoreName = Literal["sessions", "mfa", "plugins", "idp"]

_DEFAULT_HOME = Path(__file__).resolve().parents[4] / ".astraauth"
DEFAULT_ASTRAAUTH_HOME = Path(os.environ.get("ASTRAAUTH_HOME", _DEFAULT_HOME))
_CONFIG_FILENAME = "config.json"
_ENV_FILENAME = ".env"
_SETTINGS_KEY_FILENAME = "settings.key"
_SETTINGS_KEY_METADATA_FILENAME = "settings-key-metadata.json"
_ENCRYPTED_PREFIX = "enc::"
_ENV_PREFIX = "ASTRAAUTH_"
_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600


@dataclass(frozen=True)
class SettingsKeyMetadata:
    key_id: str
    created_at: datetime
    active: bool
    rotated_at: datetime | None
    algorithm: str = "fernet"


@dataclass(frozen=True)
class SettingsKeyInspection:
    key_exists: bool
    metadata_exists: bool
    metadata: SettingsKeyMetadata | None
    stale: bool
    permissions_supported: bool
    weak_permissions: tuple[str, ...]


class RelationalStoreConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    backend: DatabaseBackend = "sqlite"
    mode: DatabaseMode = "sync"
    dsn: str | None = None
    database: str = ":memory:"
    host: str = "localhost"
    port: int | None = None
    username: str | None = None
    password: str | None = None
    driver: str | None = None
    options: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_model(self) -> RelationalStoreConfig:
        if self.dsn:
            return self
        if self.backend == "sqlite":
            if not self.database:
                raise ValueError("sqlite database path must be configured")
            return self
        if not self.database:
            raise ValueError("relational database name must be configured")
        if not self.host:
            raise ValueError("relational database host must be configured")
        return self

    def validate_settings(self) -> None:
        type(self).model_validate(self.model_dump())

    def with_mode(self, mode: DatabaseMode) -> RelationalStoreConfig:
        return self.model_copy(update={"mode": mode})

    def to_dsn(self, *, mode: DatabaseMode | None = None) -> str:
        candidate = self if mode is None or mode == self.mode else self.with_mode(mode)
        candidate.validate_settings()
        if candidate.dsn is not None:
            return candidate.dsn
        if candidate.backend == "sqlite":
            return candidate._sqlite_dsn()
        return candidate._network_dsn()

    def _sqlite_dsn(self) -> str:
        scheme = "sqlite+aiosqlite" if self.mode == "async" else "sqlite"
        if self.database == ":memory:":
            return f"{scheme}:///:memory:"
        return f"{scheme}:///{Path(self.database).as_posix()}"

    def _network_dsn(self) -> str:
        scheme = self._scheme()
        auth = ""
        if self.username is not None:
            auth = quote(self.username, safe="")
            if self.password is not None:
                auth = f"{auth}:{quote(self.password, safe='')}"
            auth = f"{auth}@"
        port = self.port or self._default_port()
        query = f"?{urlencode(self.options)}" if self.options else ""
        return f"{scheme}://{auth}{self.host}:{port}/{self.database}{query}"

    def _scheme(self) -> str:
        if self.backend == "postgres":
            if self.mode == "async":
                return f"postgresql+{self.driver or 'psycopg'}"
            return "postgresql"
        if self.backend == "mysql":
            if self.mode == "async":
                return f"mysql+{self.driver or 'aiomysql'}"
            return "mysql"
        if self.mode == "async":
            return f"sqlite+{self.driver or 'aiosqlite'}"
        return "sqlite"

    def _default_port(self) -> int:
        if self.backend == "postgres":
            return 5432
        if self.backend == "mysql":
            return 3306
        raise ValueError("sqlite does not use a network port")

    @classmethod
    def sqlite_memory(cls, *, mode: DatabaseMode = "sync") -> RelationalStoreConfig:
        return cls(backend="sqlite", mode=mode, database=":memory:")

    @classmethod
    def sqlite_file(cls, path: str, *, mode: DatabaseMode = "sync") -> RelationalStoreConfig:
        return cls(backend="sqlite", mode=mode, database=path)

    @classmethod
    def postgres(
        cls,
        *,
        database: str,
        host: str = "localhost",
        port: int = 5432,
        username: str | None = None,
        password: str | None = None,
        mode: DatabaseMode = "sync",
        driver: str | None = None,
        options: dict[str, str] | None = None,
    ) -> RelationalStoreConfig:
        return cls(
            backend="postgres",
            mode=mode,
            database=database,
            host=host,
            port=port,
            username=username,
            password=password,
            driver=driver,
            options=options or {},
        )

    @classmethod
    def mysql(
        cls,
        *,
        database: str,
        host: str = "localhost",
        port: int = 3306,
        username: str | None = None,
        password: str | None = None,
        mode: DatabaseMode = "sync",
        driver: str | None = None,
        options: dict[str, str] | None = None,
    ) -> RelationalStoreConfig:
        return cls(
            backend="mysql",
            mode=mode,
            database=database,
            host=host,
            port=port,
            username=username,
            password=password,
            driver=driver,
            options=options or {},
        )


class PersistenceConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    default_database: RelationalStoreConfig = Field(
        default_factory=RelationalStoreConfig.sqlite_memory
    )
    sessions_database: RelationalStoreConfig | None = None
    mfa_database: RelationalStoreConfig | None = None
    plugins_database: RelationalStoreConfig | None = None
    idp_database: RelationalStoreConfig | None = None
    auto_create_schema: bool = True
    postgres_test_dsn: str | None = None
    postgres_test_async_dsn: str | None = None
    mysql_test_dsn: str | None = None
    mysql_test_async_dsn: str | None = None

    def validate_settings(self) -> None:
        type(self).model_validate(self.model_dump())

    def database_for(self, store: StoreName) -> RelationalStoreConfig:
        override = {
            "sessions": self.sessions_database,
            "mfa": self.mfa_database,
            "plugins": self.plugins_database,
            "idp": self.idp_database,
        }[store]
        return override or self.default_database

    def dsn_for(self, store: StoreName, *, mode: DatabaseMode | None = None) -> str:
        return self.database_for(store).to_dsn(mode=mode)

    @classmethod
    def inmemory(cls, *, async_enabled: bool = False) -> PersistenceConfig:
        mode: DatabaseMode = "async" if async_enabled else "sync"
        return cls(default_database=RelationalStoreConfig.sqlite_memory(mode=mode))

    @classmethod
    def for_project(
        cls,
        *,
        project_name: str,
        environment: EnvironmentName = "dev",
        backend: DatabaseBackend = "sqlite",
        async_enabled: bool = False,
        base_dir: str = "data",
        host: str = "localhost",
        port: int | None = None,
        username: str | None = None,
        password: str | None = None,
        database: str | None = None,
    ) -> PersistenceConfig:
        mode: DatabaseMode = "async" if async_enabled else "sync"
        slug = _slugify_project_name(project_name)
        if backend == "sqlite":
            root = Path(base_dir) / slug / environment
            return cls(
                default_database=RelationalStoreConfig.sqlite_file(
                    str(root / "astraauth.db"), mode=mode
                ),
                sessions_database=RelationalStoreConfig.sqlite_file(
                    str(root / "sessions.db"), mode=mode
                ),
                mfa_database=RelationalStoreConfig.sqlite_file(str(root / "mfa.db"), mode=mode),
                plugins_database=RelationalStoreConfig.sqlite_file(
                    str(root / "plugins.db"), mode=mode
                ),
                idp_database=RelationalStoreConfig.sqlite_file(str(root / "idp.db"), mode=mode),
            )
        if backend == "postgres":
            return cls(
                default_database=RelationalStoreConfig.postgres(
                    database=database or f"{slug}_{environment}",
                    host=host,
                    port=port or 5432,
                    username=username,
                    password=password,
                    mode=mode,
                )
            )
        return cls(
            default_database=RelationalStoreConfig.mysql(
                database=database or f"{slug}_{environment}",
                host=host,
                port=port or 3306,
                username=username,
                password=password,
                mode=mode,
            )
        )


class OIDCProviderSettings(BaseModel):
    model_config = ConfigDict(extra="ignore")

    provider_id: str
    issuer: str
    client_id: str
    client_secret: str | None = None
    discovery_url: str | None = None
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    userinfo_endpoint: str | None = None
    jwks_uri: str | None = None
    scopes: tuple[str, ...] = ("openid", "profile", "email")


class IDPConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    oidc_providers: tuple[OIDCProviderSettings, ...] = ()

    def provider_map(self) -> dict[str, OIDCProviderSettings]:
        return {provider.provider_id: provider for provider in self.oidc_providers}


class ObservabilityConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    service_name: str = "astraauth"
    structured_logging_enabled: bool = True
    metrics_enabled: bool = True
    correlation_header_name: str = "X-Correlation-ID"


class AuthConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    project_name: str = "AstraAuth"
    environment: EnvironmentName = "prod"
    issuer: str = "auth.local"
    access_token_ttl_seconds: int = 600
    clock_skew_seconds: int = 60
    signing_alg: str = "RS256"
    encryption_alg: str = "RSA-OAEP"
    encryption_enc: str = "A256GCM"
    dev_mode: bool = False
    persistence: PersistenceConfig = Field(default_factory=PersistenceConfig.inmemory)
    idp: IDPConfig = Field(default_factory=IDPConfig)
    observability: ObservabilityConfig = Field(default_factory=ObservabilityConfig)

    @model_validator(mode="after")
    def _validate_model(self) -> AuthConfig:
        if self.dev_mode and self.environment == "prod":
            raise ValueError("dev_mode cannot be enabled in production")
        if self.access_token_ttl_seconds <= 0:
            raise ValueError("access_token_ttl_seconds must be positive")
        return self

    def validate_settings(self) -> None:
        type(self).model_validate(self.model_dump())

    def save_json(
        self,
        *,
        home: Path | None = None,
        encrypt_values: bool = True,
        filename: str = _CONFIG_FILENAME,
    ) -> Path:
        target_home = home or DEFAULT_ASTRAAUTH_HOME
        ensure_private_directory(target_home)
        payload = self.model_dump(mode="json")
        if encrypt_values:
            payload = _encrypt_mapping(payload, home=target_home)
        target = target_home / filename
        write_private_text(target, json.dumps(payload, indent=2))
        return target

    def reload(
        self,
        *,
        home: Path | None = None,
        env: dict[str, str] | None = None,
        config_filename: str = _CONFIG_FILENAME,
        env_filename: str = _ENV_FILENAME,
    ) -> AuthConfig:
        return type(self).load(
            home=home,
            env=env,
            config_filename=config_filename,
            env_filename=env_filename,
        )

    @classmethod
    def load(
        cls,
        *,
        home: Path | None = None,
        env: dict[str, str] | None = None,
        config_filename: str = _CONFIG_FILENAME,
        env_filename: str = _ENV_FILENAME,
    ) -> AuthConfig:
        target_home = home or DEFAULT_ASTRAAUTH_HOME
        data = cls().model_dump(mode="json")
        data = _deep_merge(data, _load_json_settings(target_home / config_filename))
        data = _deep_merge(data, _load_dotenv_settings(target_home / env_filename))
        data = _deep_merge(data, _load_env_settings())
        if env:
            data = _deep_merge(data, _parse_env_mapping(env))
        return cls.model_validate(data)

    @classmethod
    def update_json_path(
        cls,
        path: str,
        value: Any,
        *,
        home: Path | None = None,
        filename: str = _CONFIG_FILENAME,
        encrypt_values: bool = True,
    ) -> Path:
        target_home = home or DEFAULT_ASTRAAUTH_HOME
        target = target_home / filename
        payload = _load_json_settings(target)
        updated = copy.deepcopy(payload)
        try:
            current_value = glom(updated, path)
            if current_value == value and target.exists():
                return target
        except PathAccessError:
            pass
        assign(updated, path, value, missing=dict)
        config = cls.model_validate(_deep_merge(cls().model_dump(mode="json"), updated))
        return config.save_json(home=target_home, encrypt_values=encrypt_values, filename=filename)

    @classmethod
    def for_project(
        cls,
        *,
        project_name: str,
        environment: EnvironmentName = "dev",
        persistence_backend: DatabaseBackend = "sqlite",
        async_persistence: bool = False,
        persistence_base_dir: str = "data",
        persistence_host: str = "localhost",
        persistence_port: int | None = None,
        persistence_username: str | None = None,
        persistence_password: str | None = None,
        persistence_database: str | None = None,
        issuer: str | None = None,
    ) -> AuthConfig:
        return cls(
            project_name=project_name,
            environment=environment,
            issuer=issuer or f"{_slugify_project_name(project_name)}.local",
            dev_mode=environment != "prod",
            persistence=PersistenceConfig.for_project(
                project_name=project_name,
                environment=environment,
                backend=persistence_backend,
                async_enabled=async_persistence,
                base_dir=persistence_base_dir,
                host=persistence_host,
                port=persistence_port,
                username=persistence_username,
                password=persistence_password,
                database=persistence_database,
            ),
        )


def encrypt_runtime_mapping(value: Any, *, home: Path | None = None) -> Any:
    return _encrypt_mapping(value, home=home or DEFAULT_ASTRAAUTH_HOME)


def decrypt_runtime_mapping(value: Any, *, home: Path | None = None) -> Any:
    return _decrypt_mapping(value, home=home or DEFAULT_ASTRAAUTH_HOME)


def runtime_mapping_contains_encrypted_values(value: Any) -> bool:
    return _contains_encrypted_value(value)


def ensure_private_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        path.chmod(_PRIVATE_DIRECTORY_MODE)
    return path


def write_private_text(path: Path, content: str) -> Path:
    ensure_private_directory(path.parent)
    path.write_text(content, encoding="utf-8")
    _enforce_private_file(path)
    return path


def write_private_bytes(path: Path, content: bytes) -> Path:
    ensure_private_directory(path.parent)
    path.write_bytes(content)
    _enforce_private_file(path)
    return path


def enforce_private_file_permissions(path: Path) -> Path:
    if path.exists():
        _enforce_private_file(path)
    return path


def inspect_settings_key(
    *, home: Path | None = None, stale_after_days: int = 365
) -> SettingsKeyInspection:
    target_home = home or DEFAULT_ASTRAAUTH_HOME
    key_path = target_home / "secrets" / _SETTINGS_KEY_FILENAME
    metadata_path = target_home / "secrets" / _SETTINGS_KEY_METADATA_FILENAME
    metadata = _load_settings_key_metadata(metadata_path)
    stale = False
    if metadata is not None:
        stale = (datetime.now(tz=UTC) - metadata.created_at).days >= stale_after_days
    weak_permissions: list[str] = []
    if os.name != "nt":
        for path, expected_mode in (
            (target_home, _PRIVATE_DIRECTORY_MODE),
            (target_home / "secrets", _PRIVATE_DIRECTORY_MODE),
            (key_path, _PRIVATE_FILE_MODE),
            (metadata_path, _PRIVATE_FILE_MODE),
            (target_home / _CONFIG_FILENAME, _PRIVATE_FILE_MODE),
        ):
            if path.exists() and stat.S_IMODE(path.stat().st_mode) != expected_mode:
                weak_permissions.append(str(path))
    return SettingsKeyInspection(
        key_exists=key_path.exists(),
        metadata_exists=metadata_path.exists(),
        metadata=metadata,
        stale=stale,
        permissions_supported=os.name != "nt",
        weak_permissions=tuple(weak_permissions),
    )


def rotate_settings_key(*, home: Path | None = None) -> SettingsKeyMetadata:
    target_home = home or DEFAULT_ASTRAAUTH_HOME
    key_path = target_home / "secrets" / _SETTINGS_KEY_FILENAME
    metadata_path = target_home / "secrets" / _SETTINGS_KEY_METADATA_FILENAME
    config_path = target_home / _CONFIG_FILENAME
    if not key_path.exists():
        raise FileNotFoundError(f"settings key does not exist at {key_path}")
    old_key = key_path.read_bytes()
    raw_config: Any = None
    if config_path.exists():
        raw_config = json.loads(config_path.read_text(encoding="utf-8"))
        raw_config = _transform_secret_values(raw_config, fernet=Fernet(old_key), encrypt=False)
        if _contains_encrypted_value(raw_config):
            raise ValueError(
                "config contains values that cannot be decrypted with the active settings key"
            )
    previous = _load_settings_key_metadata(metadata_path)
    now = datetime.now(tz=UTC)
    if previous is not None:
        _write_settings_key_metadata(
            metadata_path,
            SettingsKeyMetadata(
                key_id=previous.key_id,
                created_at=previous.created_at,
                active=False,
                rotated_at=now,
                algorithm=previous.algorithm,
            ),
            filename=f"settings-key-{previous.key_id}.json",
        )
    new_key = Fernet.generate_key()
    write_private_bytes(key_path, new_key)
    metadata = SettingsKeyMetadata(
        key_id=_settings_key_id(new_key),
        created_at=now,
        active=True,
        rotated_at=None,
    )
    _write_settings_key_metadata(metadata_path, metadata)
    if raw_config is not None:
        encrypted = _transform_secret_values(raw_config, fernet=Fernet(new_key), encrypt=True)
        write_private_text(config_path, json.dumps(encrypted, indent=2))
    return metadata


class _AuthConfigSettings(AuthConfig, BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix=_ENV_PREFIX,
        env_nested_delimiter="__",
        env_ignore_empty=True,
        extra="ignore",
        case_sensitive=False,
    )


def _slugify_project_name(project_name: str) -> str:
    slug = "".join(ch.lower() if ch.isalnum() else "-" for ch in project_name).strip("-")
    return slug or "astraauth"


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _settings_fernet(home: Path) -> Fernet:
    ensure_private_directory(home)
    secrets_dir = ensure_private_directory(home / "secrets")
    key_path = secrets_dir / _SETTINGS_KEY_FILENAME
    if not key_path.exists():
        key = Fernet.generate_key()
        write_private_bytes(key_path, key)
        _write_settings_key_metadata(
            secrets_dir / _SETTINGS_KEY_METADATA_FILENAME,
            SettingsKeyMetadata(
                key_id=_settings_key_id(key),
                created_at=datetime.now(tz=UTC),
                active=True,
                rotated_at=None,
            ),
        )
    elif not (secrets_dir / _SETTINGS_KEY_METADATA_FILENAME).exists():
        key = key_path.read_bytes()
        _write_settings_key_metadata(
            secrets_dir / _SETTINGS_KEY_METADATA_FILENAME,
            SettingsKeyMetadata(
                key_id=_settings_key_id(key),
                created_at=datetime.fromtimestamp(key_path.stat().st_mtime, tz=UTC),
                active=True,
                rotated_at=None,
            ),
        )
    _enforce_private_file(key_path)
    return Fernet(key_path.read_bytes())


def _encrypt_mapping(value: Any, *, home: Path) -> Any:
    return _transform_secret_values(value, fernet=_settings_fernet(home), encrypt=True)


def _decrypt_mapping(value: Any, *, home: Path) -> Any:
    return _transform_secret_values(value, fernet=_settings_fernet(home), encrypt=False)


def _transform_secret_values(value: Any, *, fernet: Fernet, encrypt: bool) -> Any:
    if isinstance(value, dict):
        return {
            key: _transform_secret_values(item, fernet=fernet, encrypt=encrypt)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_transform_secret_values(item, fernet=fernet, encrypt=encrypt) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        if encrypt:
            payload = json.dumps(value).encode("utf-8")
            return f"{_ENCRYPTED_PREFIX}{fernet.encrypt(payload).decode('utf-8')}"
        if isinstance(value, str) and value.startswith(_ENCRYPTED_PREFIX):
            token = value.removeprefix(_ENCRYPTED_PREFIX)
            try:
                decrypted = fernet.decrypt(token.encode("utf-8")).decode("utf-8")
                return json.loads(decrypted)
            except InvalidToken:
                return value
    return value


def _load_json_settings(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    return cast(dict[str, Any], _decrypt_mapping(raw, home=path.parent))


def _load_dotenv_settings(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return dict(
        DotEnvSettingsSource(
            _AuthConfigSettings,
            env_file=path,
            env_file_encoding="utf-8",
        )()
    )


def _load_env_settings() -> dict[str, Any]:
    return dict(EnvSettingsSource(_AuthConfigSettings)())


def _parse_env_mapping(values: dict[str, str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, raw_value in values.items():
        if not key.startswith(_ENV_PREFIX):
            continue
        path = key[len(_ENV_PREFIX) :].lower().split("__")
        _assign_nested(result, path, _parse_scalar(raw_value))
    return result


def _assign_nested(target: dict[str, Any], path: list[str], value: Any) -> None:
    cursor = target
    for part in path[:-1]:
        cursor = cursor.setdefault(part, {})
    cursor[path[-1]] = value


def _parse_scalar(raw: str) -> Any:
    lowered = raw.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def _enforce_private_file(path: Path) -> None:
    if os.name != "nt":
        path.chmod(_PRIVATE_FILE_MODE)


def _settings_key_id(key: bytes) -> str:
    return f"settings-{hashlib.sha256(key).hexdigest()[:16]}"


def _write_settings_key_metadata(
    path: Path,
    metadata: SettingsKeyMetadata,
    *,
    filename: str | None = None,
) -> Path:
    target = path if filename is None else path.parent / filename
    payload = asdict(metadata)
    payload["created_at"] = metadata.created_at.isoformat()
    payload["rotated_at"] = metadata.rotated_at.isoformat() if metadata.rotated_at else None
    payload["metadata_id"] = str(uuid4())
    return write_private_text(target, json.dumps(payload, indent=2))


def _load_settings_key_metadata(path: Path) -> SettingsKeyMetadata | None:
    if not path.exists():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    return SettingsKeyMetadata(
        key_id=str(payload["key_id"]),
        created_at=datetime.fromisoformat(str(payload["created_at"])),
        active=bool(payload["active"]),
        rotated_at=(
            datetime.fromisoformat(str(payload["rotated_at"]))
            if payload.get("rotated_at") is not None
            else None
        ),
        algorithm=str(payload.get("algorithm", "fernet")),
    )


def _contains_encrypted_value(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_contains_encrypted_value(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_encrypted_value(item) for item in value)
    return isinstance(value, str) and value.startswith(_ENCRYPTED_PREFIX)
