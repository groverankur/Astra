from astraauth.core.plugins import InMemoryTenantPluginRegistryStore, SQLTenantPluginRegistryStore


def test_inmemory_plugin_registry_roundtrip() -> None:
    store = InMemoryTenantPluginRegistryStore()
    store.enable(tenant_id="t1", plugin_name="geo")
    store.enable(tenant_id="t1", plugin_name="risk")
    assert store.enabled_for_tenant(tenant_id="t1") == {"geo", "risk"}
    store.disable(tenant_id="t1", plugin_name="geo")
    assert store.enabled_for_tenant(tenant_id="t1") == {"risk"}


def test_sql_plugin_registry_roundtrip() -> None:
    store = SQLTenantPluginRegistryStore(":memory:")
    store.enable(tenant_id="t1", plugin_name="geo")
    store.enable(tenant_id="t1", plugin_name="risk")
    assert store.enabled_for_tenant(tenant_id="t1") == {"geo", "risk"}
    store.disable(tenant_id="t1", plugin_name="risk")
    assert store.enabled_for_tenant(tenant_id="t1") == {"geo"}
