from __future__ import annotations

import json
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from time import monotonic
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from astraauth.core.plugins import InMemoryTenantPluginRegistryStore, TenantPluginRegistryStore
from astraauth.plugins.contracts import (
    ColumnExtension,
    EndpointExecutionReport,
    EndpointExtension,
    HookError,
    HookErrorClass,
    HookExecutionReport,
    HookName,
    Plugin,
    PluginAuditRecord,
    PluginExecutionError,
    PluginManifest,
    TableExtension,
)


@dataclass(frozen=True)
class PluginTrustPolicy:
    allowed_plugins: frozenset[str] | None = None
    allowed_versions: dict[str, str] | None = None
    allowed_digests: dict[str, frozenset[str]] | None = None
    allowed_source_fingerprints: dict[str, frozenset[str]] | None = None
    tenant_allowed_plugins: dict[str, frozenset[str]] | None = None
    require_signatures: bool = False
    trusted_public_keys: tuple[bytes, ...] = ()
    max_timeout_ms: int = 5_000


def plugin_manifest_payload(manifest: PluginManifest) -> bytes:
    return json.dumps(
        {
            "name": manifest.name,
            "version": manifest.version,
            "digest": manifest.digest,
            "hooks": list(manifest.hooks),
            "endpoints": list(manifest.endpoints),
            "requested_permissions": list(manifest.requested_permissions),
            "source_fingerprint": manifest.source_fingerprint,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sign_plugin_manifest(manifest: PluginManifest, private_key_pem: bytes) -> PluginManifest:
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("plugin manifest signing key must be an RSA private key")
    signature = private_key.sign(
        plugin_manifest_payload(manifest),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return PluginManifest(
        name=manifest.name,
        version=manifest.version,
        digest=manifest.digest,
        hooks=manifest.hooks,
        endpoints=manifest.endpoints,
        requested_permissions=manifest.requested_permissions,
        source_fingerprint=manifest.source_fingerprint,
        signature=signature.hex(),
    )


class PluginRuntime:
    def __init__(
        self,
        *,
        core_routes: set[str] | None = None,
        allowed_column_tables: set[str] | None = None,
        registry_store: TenantPluginRegistryStore | None = None,
        default_timeout_ms: int = 500,
        trust_policy: PluginTrustPolicy | None = None,
        audit_callback: Callable[[PluginAuditRecord], None] | None = None,
    ) -> None:
        self._plugins: dict[str, Plugin] = {}
        self._registry_store = registry_store or InMemoryTenantPluginRegistryStore()
        self._core_routes = core_routes or {
            "/authorize",
            "/token",
            "/logout",
            "/introspect",
            "/.well-known/jwks.json",
            "/.well-known/openid-configuration",
        }
        self._allowed_column_tables = allowed_column_tables or set()
        self._default_timeout_ms = default_timeout_ms
        self._trust_policy = trust_policy or PluginTrustPolicy()
        self._executor = ThreadPoolExecutor(max_workers=8)
        self._audit_records: list[PluginAuditRecord] = []
        self._audit_callback = audit_callback

    def register(self, plugin: Plugin, *, manifest: PluginManifest | None = None) -> None:
        if plugin.name in self._plugins:
            raise ValueError(f"Plugin '{plugin.name}' is already registered")
        try:
            self._validate_plugin_trust(plugin, manifest=manifest)
        except ValueError as exc:
            self._record_lifecycle_audit(
                plugin_name=plugin.name,
                target="register",
                status="failed",
                classification=HookErrorClass.TRUST,
                message=str(exc),
            )
            raise
        self._plugins[plugin.name] = plugin
        self._record_lifecycle_audit(plugin_name=plugin.name, target="register", status="succeeded")

    def enable_for_tenant(self, *, tenant_id: str, plugin_name: str) -> None:
        if plugin_name not in self._plugins:
            raise ValueError(f"Plugin '{plugin_name}' is not registered")
        allowed = self._trust_policy.tenant_allowed_plugins
        if allowed is not None and plugin_name not in allowed.get(tenant_id, frozenset()):
            message = f"Plugin '{plugin_name}' is not allowed for tenant '{tenant_id}'"
            self._record_lifecycle_audit(
                tenant_id=tenant_id,
                plugin_name=plugin_name,
                target="enable",
                status="failed",
                classification=HookErrorClass.TRUST,
                message=message,
            )
            raise ValueError(message)
        self._registry_store.enable(tenant_id=tenant_id, plugin_name=plugin_name)
        self._record_lifecycle_audit(
            tenant_id=tenant_id,
            plugin_name=plugin_name,
            target="enable",
            status="succeeded",
        )

    def disable_for_tenant(self, *, tenant_id: str, plugin_name: str) -> None:
        self._registry_store.disable(tenant_id=tenant_id, plugin_name=plugin_name)
        self._record_lifecycle_audit(
            tenant_id=tenant_id,
            plugin_name=plugin_name,
            target="disable",
            status="succeeded",
        )

    def enabled_plugins(self, *, tenant_id: str) -> tuple[Plugin, ...]:
        names = self._registry_store.enabled_for_tenant(tenant_id=tenant_id)
        plugins = [self._plugins[name] for name in names if name in self._plugins]
        return tuple(sorted(plugins, key=lambda p: (p.order, p.name)))

    def execute_hook(
        self,
        *,
        hook: HookName,
        tenant_id: str,
        payload: dict[str, Any],
        fail_closed: bool = True,
    ) -> HookExecutionReport:
        current_payload = dict(payload)
        executed: list[str] = []
        errors: list[HookError] = []

        for plugin in self.enabled_plugins(tenant_id=tenant_id):
            handler = plugin.hooks().get(hook)
            if handler is None:
                continue

            executed.append(plugin.name)
            started = monotonic()
            try:
                timeout_ms = self._effective_timeout_ms(
                    getattr(plugin, "timeout_ms", self._default_timeout_ms)
                )
                future = self._executor.submit(handler, dict(current_payload))
                result = future.result(timeout=max(timeout_ms / 1000.0, 0.001))
                if result is not None:
                    current_payload.update(result)
                self._record_audit(
                    PluginAuditRecord(
                        tenant_id=tenant_id,
                        plugin_name=plugin.name,
                        target=hook,
                        execution_type="hook",
                        status="succeeded",
                        fail_closed=fail_closed,
                        duration_ms=self._duration_ms(started),
                    )
                )
            except FutureTimeoutError as exc:
                error = HookError(
                    plugin_name=plugin.name,
                    classification=HookErrorClass.TIMEOUT,
                    message=f"Plugin hook timed out after {timeout_ms}ms",
                )
                future.cancel()
                errors.append(error)
                self._record_audit(
                    PluginAuditRecord(
                        tenant_id=tenant_id,
                        plugin_name=plugin.name,
                        target=hook,
                        execution_type="hook",
                        status="failed",
                        fail_closed=fail_closed,
                        duration_ms=self._duration_ms(started),
                        error_classification=error.classification.value,
                        message=error.message,
                    )
                )
                if fail_closed:
                    raise PluginExecutionError(
                        f"Plugin hook execution failed for {hook}: {error.plugin_name}: {error.message}"
                    ) from exc
            except ValueError as exc:
                error = HookError(
                    plugin_name=plugin.name,
                    classification=HookErrorClass.VALIDATION,
                    message=str(exc),
                )
                errors.append(error)
                self._record_audit(
                    PluginAuditRecord(
                        tenant_id=tenant_id,
                        plugin_name=plugin.name,
                        target=hook,
                        execution_type="hook",
                        status="failed",
                        fail_closed=fail_closed,
                        duration_ms=self._duration_ms(started),
                        error_classification=error.classification.value,
                        message=error.message,
                    )
                )
                if fail_closed:
                    raise PluginExecutionError(
                        f"Plugin hook execution failed for {hook}: {error.plugin_name}: {error.message}"
                    ) from exc
            except Exception as exc:
                error = HookError(
                    plugin_name=plugin.name,
                    classification=HookErrorClass.RUNTIME,
                    message=str(exc),
                )
                errors.append(error)
                self._record_audit(
                    PluginAuditRecord(
                        tenant_id=tenant_id,
                        plugin_name=plugin.name,
                        target=hook,
                        execution_type="hook",
                        status="failed",
                        fail_closed=fail_closed,
                        duration_ms=self._duration_ms(started),
                        error_classification=error.classification.value,
                        message=error.message,
                    )
                )
                if fail_closed:
                    raise PluginExecutionError(
                        f"Plugin hook execution failed for {hook}: {error.plugin_name}: {error.message}"
                    ) from exc

        return HookExecutionReport(
            hook=hook,
            tenant_id=tenant_id,
            payload=current_payload,
            executed_plugins=tuple(executed),
            errors=tuple(errors),
        )

    def invoke_endpoint(
        self,
        *,
        tenant_id: str,
        extension: EndpointExtension,
        payload: dict[str, Any],
        fail_closed: bool = True,
    ) -> EndpointExecutionReport:
        self._validate_endpoint_extension(extension)
        timeout_ms = int(
            getattr(
                self._plugins.get(extension.plugin_name), "timeout_ms", self._default_timeout_ms
            )
        )
        timeout_ms = self._effective_timeout_ms(timeout_ms)
        started = monotonic()
        errors: list[HookError] = []
        try:
            future = self._executor.submit(extension.handler, dict(payload))
            result = future.result(timeout=max(timeout_ms / 1000.0, 0.001))
            self._record_audit(
                PluginAuditRecord(
                    tenant_id=tenant_id,
                    plugin_name=extension.plugin_name,
                    target=extension.path,
                    execution_type="endpoint",
                    status="succeeded",
                    fail_closed=fail_closed,
                    duration_ms=self._duration_ms(started),
                )
            )
            return EndpointExecutionReport(
                tenant_id=tenant_id,
                plugin_name=extension.plugin_name,
                path=extension.path,
                methods=extension.methods,
                result=result,
                errors=(),
            )
        except FutureTimeoutError as exc:
            error = HookError(
                plugin_name=extension.plugin_name,
                classification=HookErrorClass.TIMEOUT,
                message=f"Plugin endpoint timed out after {timeout_ms}ms",
            )
            future.cancel()
            errors.append(error)
            self._record_audit(
                PluginAuditRecord(
                    tenant_id=tenant_id,
                    plugin_name=extension.plugin_name,
                    target=extension.path,
                    execution_type="endpoint",
                    status="failed",
                    fail_closed=fail_closed,
                    duration_ms=self._duration_ms(started),
                    error_classification=error.classification.value,
                    message=error.message,
                )
            )
            if fail_closed:
                raise PluginExecutionError(
                    f"Plugin endpoint execution failed for {extension.path}: {error.plugin_name}: {error.message}"
                ) from exc
        except ValueError as exc:
            error = HookError(
                plugin_name=extension.plugin_name,
                classification=HookErrorClass.VALIDATION,
                message=str(exc),
            )
            errors.append(error)
            self._record_audit(
                PluginAuditRecord(
                    tenant_id=tenant_id,
                    plugin_name=extension.plugin_name,
                    target=extension.path,
                    execution_type="endpoint",
                    status="failed",
                    fail_closed=fail_closed,
                    duration_ms=self._duration_ms(started),
                    error_classification=error.classification.value,
                    message=error.message,
                )
            )
            if fail_closed:
                raise PluginExecutionError(
                    f"Plugin endpoint execution failed for {extension.path}: {error.plugin_name}: {error.message}"
                ) from exc
        except Exception as exc:
            error = HookError(
                plugin_name=extension.plugin_name,
                classification=HookErrorClass.RUNTIME,
                message=str(exc),
            )
            errors.append(error)
            self._record_audit(
                PluginAuditRecord(
                    tenant_id=tenant_id,
                    plugin_name=extension.plugin_name,
                    target=extension.path,
                    execution_type="endpoint",
                    status="failed",
                    fail_closed=fail_closed,
                    duration_ms=self._duration_ms(started),
                    error_classification=error.classification.value,
                    message=error.message,
                )
            )
            if fail_closed:
                raise PluginExecutionError(
                    f"Plugin endpoint execution failed for {extension.path}: {error.plugin_name}: {error.message}"
                ) from exc
        return EndpointExecutionReport(
            tenant_id=tenant_id,
            plugin_name=extension.plugin_name,
            path=extension.path,
            methods=extension.methods,
            result=None,
            errors=tuple(errors),
        )

    def endpoint_extensions(self, *, tenant_id: str) -> tuple[EndpointExtension, ...]:
        extensions: list[EndpointExtension] = []
        seen_routes: set[tuple[str, str]] = set()
        for plugin in self.enabled_plugins(tenant_id=tenant_id):
            for ext in plugin.register_endpoints():
                self._validate_endpoint_extension(ext)
                for method in ext.methods:
                    route_key = (ext.path, method.upper())
                    if route_key in seen_routes:
                        raise ValueError(
                            f"Endpoint '{ext.path}' with method '{method.upper()}' is already registered"
                        )
                    seen_routes.add(route_key)
                extensions.append(ext)
        return tuple(extensions)

    def table_extensions(self, *, tenant_id: str) -> tuple[TableExtension, ...]:
        extensions: list[TableExtension] = []
        for plugin in self.enabled_plugins(tenant_id=tenant_id):
            for ext in plugin.register_tables():
                self._validate_table_extension(ext)
                extensions.append(ext)
        return tuple(extensions)

    def column_extensions(self, *, tenant_id: str) -> tuple[ColumnExtension, ...]:
        extensions: list[ColumnExtension] = []
        for plugin in self.enabled_plugins(tenant_id=tenant_id):
            for ext in plugin.register_columns():
                self._validate_column_extension(ext)
                extensions.append(ext)
        return tuple(extensions)

    def _validate_endpoint_extension(self, ext: EndpointExtension) -> None:
        namespace = f"/auth/ext/{ext.plugin_name}"
        if not ext.path.startswith(namespace):
            raise ValueError(f"Endpoint '{ext.path}' is not namespaced under '{namespace}'")
        if ext.path in self._core_routes:
            raise ValueError(f"Endpoint '{ext.path}' cannot override core routes")
        if not ext.methods:
            raise ValueError(f"Endpoint '{ext.path}' must define at least one method")

    def _validate_table_extension(self, ext: TableExtension) -> None:
        required_prefix = f"plugin_{ext.plugin_name}_"
        if not ext.table_name.startswith(required_prefix):
            raise ValueError(
                f"Table '{ext.table_name}' must be namespaced with '{required_prefix}'"
            )

    def _validate_column_extension(self, ext: ColumnExtension) -> None:
        if ext.table_name not in self._allowed_column_tables:
            raise ValueError(f"Column extension table '{ext.table_name}' is not in allow-list")

    def tenant_plugins(self) -> dict[str, tuple[str, ...]]:
        result: dict[str, tuple[str, ...]] = {}
        for tenant_id, names in self._registry_store.all_tenants().items():
            result[tenant_id] = tuple(sorted(names))
        return result

    def registered_plugin_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._plugins))

    def audit_records(self) -> tuple[PluginAuditRecord, ...]:
        return tuple(self._audit_records)

    def clear_audit_records(self) -> None:
        self._audit_records.clear()

    def _validate_plugin_trust(self, plugin: Plugin, *, manifest: PluginManifest | None) -> None:
        policy = self._trust_policy
        if policy.allowed_plugins is not None and plugin.name not in policy.allowed_plugins:
            raise ValueError(f"Plugin '{plugin.name}' is not in the allowlist")
        if manifest is None:
            if policy.require_signatures:
                raise ValueError(f"Plugin '{plugin.name}' requires a signed manifest")
            return
        if manifest.name != plugin.name:
            raise ValueError("plugin manifest name does not match plugin")
        self._validate_manifest_policy(manifest)
        if policy.require_signatures or manifest.signature is not None:
            self._verify_plugin_manifest_signature(manifest)

    def _validate_manifest_policy(self, manifest: PluginManifest) -> None:
        policy = self._trust_policy
        if policy.allowed_versions is not None:
            spec = policy.allowed_versions.get(manifest.name)
            if spec is not None:
                try:
                    if Version(manifest.version) not in SpecifierSet(spec):
                        raise ValueError(
                            f"Plugin '{manifest.name}' version '{manifest.version}' "
                            f"is outside allowed range '{spec}'"
                        )
                except (InvalidSpecifier, InvalidVersion) as exc:
                    raise ValueError(
                        f"Plugin '{manifest.name}' has invalid version policy or manifest version"
                    ) from exc
        if policy.allowed_digests is not None:
            allowed_digests = policy.allowed_digests.get(manifest.name)
            if allowed_digests is not None and manifest.digest not in allowed_digests:
                raise ValueError(f"Plugin '{manifest.name}' digest is not allowed")
        if policy.allowed_source_fingerprints is not None:
            allowed_sources = policy.allowed_source_fingerprints.get(manifest.name)
            if allowed_sources is not None and manifest.source_fingerprint not in allowed_sources:
                raise ValueError(f"Plugin '{manifest.name}' source fingerprint is not allowed")

    def _verify_plugin_manifest_signature(self, manifest: PluginManifest) -> None:
        if manifest.signature is None:
            raise ValueError(f"Plugin '{manifest.name}' manifest is unsigned")
        if not self._trust_policy.trusted_public_keys:
            raise ValueError("no trusted plugin signing keys configured")
        signature = bytes.fromhex(manifest.signature)
        payload = plugin_manifest_payload(manifest)
        for key_pem in self._trust_policy.trusted_public_keys:
            public_key = serialization.load_pem_public_key(key_pem)
            if not isinstance(public_key, rsa.RSAPublicKey):
                continue
            try:
                public_key.verify(
                    signature,
                    payload,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256(),
                )
                return
            except InvalidSignature:
                continue
        raise ValueError(f"Plugin '{manifest.name}' manifest signature is not trusted")

    def _effective_timeout_ms(self, requested_timeout_ms: object) -> int:
        requested: int
        try:
            if isinstance(requested_timeout_ms, int):
                requested = requested_timeout_ms
            elif isinstance(requested_timeout_ms, str | bytes | bytearray):
                requested = int(requested_timeout_ms)
            else:
                requested = self._default_timeout_ms
        except (TypeError, ValueError):
            requested = self._default_timeout_ms
        max_timeout = max(1, self._trust_policy.max_timeout_ms)
        return min(max(requested, 1), max_timeout)

    def _record_lifecycle_audit(
        self,
        *,
        plugin_name: str,
        target: str,
        status: str,
        tenant_id: str = "system",
        classification: HookErrorClass | None = None,
        message: str | None = None,
    ) -> None:
        self._record_audit(
            PluginAuditRecord(
                tenant_id=tenant_id,
                plugin_name=plugin_name,
                target=target,
                execution_type="lifecycle",
                status="succeeded" if status == "succeeded" else "failed",
                fail_closed=True,
                duration_ms=0,
                error_classification=classification.value if classification is not None else None,
                message=message,
            )
        )

    def _record_audit(self, record: PluginAuditRecord) -> None:
        self._audit_records.append(record)
        if len(self._audit_records) > 512:
            del self._audit_records[: len(self._audit_records) - 512]
        if self._audit_callback is not None:
            self._audit_callback(record)

    def _duration_ms(self, started: float) -> int:
        return max(0, int((monotonic() - started) * 1000))
