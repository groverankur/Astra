from __future__ import annotations

from typing import Protocol

from astraauth.core.persistence import (
    AsyncRelationalDatabase,
    RelationalDatabase,
    compile_sql,
    create_async_database,
    create_sync_database,
    upsert_sql,
)


class TenantPluginRegistryStore(Protocol):
    def enable(self, *, tenant_id: str, plugin_name: str) -> None: ...
    def disable(self, *, tenant_id: str, plugin_name: str) -> None: ...
    def enabled_for_tenant(self, *, tenant_id: str) -> set[str]: ...
    def all_tenants(self) -> dict[str, set[str]]: ...


class InMemoryTenantPluginRegistryStore:
    def __init__(self) -> None:
        self._enabled: dict[str, set[str]] = {}

    def enable(self, *, tenant_id: str, plugin_name: str) -> None:
        self._enabled.setdefault(tenant_id, set()).add(plugin_name)

    def disable(self, *, tenant_id: str, plugin_name: str) -> None:
        self._enabled.setdefault(tenant_id, set()).discard(plugin_name)

    def enabled_for_tenant(self, *, tenant_id: str) -> set[str]:
        return set(self._enabled.get(tenant_id, set()))

    def all_tenants(self) -> dict[str, set[str]]:
        return {tenant: set(plugins) for tenant, plugins in self._enabled.items()}


class SQLTenantPluginRegistryStore:
    def __init__(
        self, dsn: str = ":memory:", *, database: RelationalDatabase | None = None
    ) -> None:
        self._database = database or create_sync_database(dsn)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        ddl = """
        CREATE TABLE IF NOT EXISTS tenant_plugin_registry (
            tenant_id VARCHAR(255) NOT NULL,
            plugin_name VARCHAR(255) NOT NULL,
            PRIMARY KEY (tenant_id, plugin_name)
        )
        """
        with self._database.connection() as conn:
            conn.execute(ddl)
            conn.commit()

    def enable(self, *, tenant_id: str, plugin_name: str) -> None:
        sql = upsert_sql(
            table="tenant_plugin_registry",
            columns=("tenant_id", "plugin_name"),
            conflict_columns=("tenant_id", "plugin_name"),
            dialect=self._database.dialect,
        )
        compiled = compile_sql(
            sql,
            {"tenant_id": tenant_id, "plugin_name": plugin_name},
            self._database.dialect,
        )
        with self._database.connection() as conn:
            conn.execute(compiled.sql, compiled.params)
            conn.commit()

    def disable(self, *, tenant_id: str, plugin_name: str) -> None:
        compiled = compile_sql(
            "DELETE FROM tenant_plugin_registry WHERE tenant_id = {{tenant_id}} AND plugin_name = {{plugin_name}}",
            {"tenant_id": tenant_id, "plugin_name": plugin_name},
            self._database.dialect,
        )
        with self._database.connection() as conn:
            conn.execute(compiled.sql, compiled.params)
            conn.commit()

    def enabled_for_tenant(self, *, tenant_id: str) -> set[str]:
        compiled = compile_sql(
            "SELECT plugin_name FROM tenant_plugin_registry WHERE tenant_id = {{tenant_id}}",
            {"tenant_id": tenant_id},
            self._database.dialect,
        )
        with self._database.connection() as conn:
            rows = conn.execute(compiled.sql, compiled.params).fetchall()
            return {str(row["plugin_name"]) for row in rows}

    def all_tenants(self) -> dict[str, set[str]]:
        with self._database.connection() as conn:
            rows = conn.execute(
                "SELECT tenant_id, plugin_name FROM tenant_plugin_registry"
            ).fetchall()
            result: dict[str, set[str]] = {}
            for row in rows:
                tenant = str(row["tenant_id"])
                result.setdefault(tenant, set()).add(str(row["plugin_name"]))
            return result


class AsyncSQLTenantPluginRegistryStore:
    def __init__(
        self, dsn: str = ":memory:", *, database: AsyncRelationalDatabase | None = None
    ) -> None:
        self._database = database or create_async_database(dsn)

    async def close(self) -> None:
        await self._database.close()

    async def ensure_schema(self) -> None:
        ddl = """
        CREATE TABLE IF NOT EXISTS tenant_plugin_registry (
            tenant_id TEXT NOT NULL,
            plugin_name TEXT NOT NULL,
            PRIMARY KEY (tenant_id, plugin_name)
        )
        """
        conn = await self._database.connection()
        await conn.execute(ddl)
        await conn.commit()

    async def enable(self, *, tenant_id: str, plugin_name: str) -> None:
        sql = upsert_sql(
            table="tenant_plugin_registry",
            columns=("tenant_id", "plugin_name"),
            conflict_columns=("tenant_id", "plugin_name"),
            dialect=self._database.dialect,
        )
        compiled = compile_sql(
            sql,
            {"tenant_id": tenant_id, "plugin_name": plugin_name},
            self._database.dialect,
        )
        conn = await self._database.connection()
        await conn.execute(compiled.sql, compiled.params)
        await conn.commit()

    async def disable(self, *, tenant_id: str, plugin_name: str) -> None:
        compiled = compile_sql(
            "DELETE FROM tenant_plugin_registry WHERE tenant_id = {{tenant_id}} AND plugin_name = {{plugin_name}}",
            {"tenant_id": tenant_id, "plugin_name": plugin_name},
            self._database.dialect,
        )
        conn = await self._database.connection()
        await conn.execute(compiled.sql, compiled.params)
        await conn.commit()

    async def enabled_for_tenant(self, *, tenant_id: str) -> set[str]:
        compiled = compile_sql(
            "SELECT plugin_name FROM tenant_plugin_registry WHERE tenant_id = {{tenant_id}}",
            {"tenant_id": tenant_id},
            self._database.dialect,
        )
        conn = await self._database.connection()
        cursor = await conn.execute(compiled.sql, compiled.params)
        rows = await cursor.fetchall()
        return {str(row["plugin_name"]) for row in rows}

    async def all_tenants(self) -> dict[str, set[str]]:
        conn = await self._database.connection()
        cursor = await conn.execute("SELECT tenant_id, plugin_name FROM tenant_plugin_registry")
        rows = await cursor.fetchall()
        result: dict[str, set[str]] = {}
        for row in rows:
            result.setdefault(str(row["tenant_id"]), set()).add(str(row["plugin_name"]))
        return result


TenantPluginRegistryRepository = TenantPluginRegistryStore
InMemoryTenantPluginRegistryRepository = InMemoryTenantPluginRegistryStore
SQLTenantPluginRegistryRepository = SQLTenantPluginRegistryStore
AsyncSQLTenantPluginRegistryRepository = AsyncSQLTenantPluginRegistryStore
