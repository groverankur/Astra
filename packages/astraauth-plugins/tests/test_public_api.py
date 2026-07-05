from astraauth_plugins import (
    GeoPlugin,
    GeoSignalPlugin,
    PluginRuntime,
    RiskPlugin,
    RiskSignalPlugin,
)


def test_builtin_plugin_aliases_remain_compatible() -> None:
    assert GeoPlugin is GeoSignalPlugin
    assert RiskPlugin is RiskSignalPlugin


def test_release_facing_builtin_names_work_with_runtime() -> None:
    runtime = PluginRuntime()
    runtime.register(GeoSignalPlugin())
    runtime.register(RiskSignalPlugin())
    runtime.enable_for_tenant(tenant_id="tenant-1", plugin_name="geo")
    runtime.enable_for_tenant(tenant_id="tenant-1", plugin_name="risk")

    names = tuple(plugin.name for plugin in runtime.enabled_plugins(tenant_id="tenant-1"))
    assert names == ("geo", "risk")
