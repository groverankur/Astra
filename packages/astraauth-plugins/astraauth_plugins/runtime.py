from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from typing import Any

from astraauth_core.plugins import InMemoryTenantPluginRegistryStore, TenantPluginRegistryStore

from astraauth_plugins.contracts import (
    ColumnExtension,
    EndpointExtension,
    HookError,
    HookErrorClass,
    HookExecutionReport,
    HookName,
    Plugin,
    PluginExecutionError,
    TableExtension,
)


class PluginRuntime:
    def __init__(
        self,
        *,
        core_routes: set[str] | None = None,
        allowed_column_tables: set[str] | None = None,
        registry_store: TenantPluginRegistryStore | None = None,
        default_timeout_ms: int = 500,
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

    def register(self, plugin: Plugin) -> None:
        if plugin.name in self._plugins:
            raise ValueError(f"Plugin '{plugin.name}' is already registered")
        self._plugins[plugin.name] = plugin

    def enable_for_tenant(self, *, tenant_id: str, plugin_name: str) -> None:
        if plugin_name not in self._plugins:
            raise ValueError(f"Plugin '{plugin_name}' is not registered")
        self._registry_store.enable(tenant_id=tenant_id, plugin_name=plugin_name)

    def disable_for_tenant(self, *, tenant_id: str, plugin_name: str) -> None:
        self._registry_store.disable(tenant_id=tenant_id, plugin_name=plugin_name)

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
            try:
                timeout_ms = int(getattr(plugin, "timeout_ms", self._default_timeout_ms))
                with ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(handler, dict(current_payload))
                    result = future.result(timeout=max(timeout_ms / 1000.0, 0.001))
                if result is not None:
                    current_payload.update(result)
            except FutureTimeoutError as exc:
                error = HookError(
                    plugin_name=plugin.name,
                    classification=HookErrorClass.TIMEOUT,
                    message=f"Plugin hook timed out after {timeout_ms}ms",
                )
                errors.append(error)
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

    def endpoint_extensions(self, *, tenant_id: str) -> tuple[EndpointExtension, ...]:
        extensions: list[EndpointExtension] = []
        for plugin in self.enabled_plugins(tenant_id=tenant_id):
            for ext in plugin.register_endpoints():
                self._validate_endpoint_extension(ext)
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
            raise ValueError(
                f"Endpoint '{ext.path}' is not namespaced under '{namespace}'"
            )
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
            raise ValueError(
                f"Column extension table '{ext.table_name}' is not in allow-list"
            )

    def tenant_plugins(self) -> dict[str, tuple[str, ...]]:
        result: dict[str, tuple[str, ...]] = {}
        for tenant_id, names in self._registry_store.all_tenants().items():
            result[tenant_id] = tuple(sorted(names))
        return result

    def registered_plugin_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._plugins))
