# mypy: disable-error-code="func-returns-value"

import time
from dataclasses import dataclass
from typing import Any

import pytest
from astraauth_plugins.contracts import (
    ColumnExtension,
    EndpointExtension,
    HookErrorClass,
    HookName,
    PluginExecutionError,
    TableExtension,
)
from astraauth_plugins.runtime import PluginRuntime


@dataclass
class DummyPlugin:
    name: str
    order: int
    _hooks: dict[HookName, Any]
    _endpoints: tuple[EndpointExtension, ...] = ()
    _tables: tuple[TableExtension, ...] = ()
    _columns: tuple[ColumnExtension, ...] = ()

    def hooks(self) -> dict[HookName, Any]:
        return self._hooks

    def register_endpoints(self) -> tuple[EndpointExtension, ...]:
        return self._endpoints

    def register_tables(self) -> tuple[TableExtension, ...]:
        return self._tables

    def register_columns(self) -> tuple[ColumnExtension, ...]:
        return self._columns


def test_deterministic_hook_execution_order_per_tenant() -> None:
    runtime = PluginRuntime()
    seen: list[str] = []

    p1 = DummyPlugin(
        name="risk",
        order=20,
        _hooks={"auth.pre_authenticate": lambda p: seen.append("risk") or None},
    )
    p2 = DummyPlugin(
        name="geo",
        order=10,
        _hooks={"auth.pre_authenticate": lambda p: seen.append("geo") or None},
    )

    runtime.register(p1)
    runtime.register(p2)
    runtime.enable_for_tenant(tenant_id="t1", plugin_name="risk")
    runtime.enable_for_tenant(tenant_id="t1", plugin_name="geo")

    report = runtime.execute_hook(
        hook="auth.pre_authenticate",
        tenant_id="t1",
        payload={"x": 1},
    )

    assert seen == ["geo", "risk"]
    assert report.executed_plugins == ("geo", "risk")


def test_hook_failure_modes_fail_open_and_fail_closed() -> None:
    runtime = PluginRuntime()
    runtime.register(
        DummyPlugin(
            name="bad",
            order=1,
            _hooks={"auth.pre_authorize": lambda p: (_ for _ in ()).throw(ValueError("boom"))},
        )
    )
    runtime.enable_for_tenant(tenant_id="t1", plugin_name="bad")

    report = runtime.execute_hook(
        hook="auth.pre_authorize",
        tenant_id="t1",
        payload={},
        fail_closed=False,
    )
    assert report.errors

    with pytest.raises(PluginExecutionError):
        runtime.execute_hook(
            hook="auth.pre_authorize",
            tenant_id="t1",
            payload={},
            fail_closed=True,
        )


def test_endpoint_extension_must_be_namespaced_and_not_core() -> None:
    runtime = PluginRuntime()
    runtime.register(
        DummyPlugin(
            name="risk",
            order=1,
            _hooks={},
            _endpoints=(EndpointExtension("risk", "/token", ("GET",), lambda p: {"ok": True}),),
        )
    )
    runtime.enable_for_tenant(tenant_id="t1", plugin_name="risk")

    with pytest.raises(ValueError):
        runtime.endpoint_extensions(tenant_id="t1")


def test_table_and_column_extension_rules() -> None:
    runtime = PluginRuntime(allowed_column_tables={"plugin_risk_extension"})
    runtime.register(
        DummyPlugin(
            name="risk",
            order=1,
            _hooks={},
            _tables=(TableExtension("risk", "plugin_risk_events"),),
            _columns=(ColumnExtension("risk", "plugin_risk_extension", "risk_score"),),
        )
    )
    runtime.enable_for_tenant(tenant_id="t1", plugin_name="risk")

    tables = runtime.table_extensions(tenant_id="t1")
    columns = runtime.column_extensions(tenant_id="t1")
    assert tables[0].table_name == "plugin_risk_events"
    assert columns[0].column_name == "risk_score"


def test_timeout_and_error_classification() -> None:
    runtime = PluginRuntime(default_timeout_ms=10)

    @dataclass
    class SlowPlugin:
        name: str = "slow"
        order: int = 1
        timeout_ms: int = 5

        def hooks(self) -> dict[HookName, Any]:
            return {"auth.post_authorize": self._slow_hook}

        def register_endpoints(self) -> tuple[EndpointExtension, ...]:
            return ()

        def register_tables(self) -> tuple[TableExtension, ...]:
            return ()

        def register_columns(self) -> tuple[ColumnExtension, ...]:
            return ()

        def _slow_hook(self, payload: dict[str, Any]) -> dict[str, Any]:
            time.sleep(0.05)
            return payload

    runtime.register(SlowPlugin())
    runtime.enable_for_tenant(tenant_id="t1", plugin_name="slow")

    report = runtime.execute_hook(
        hook="auth.post_authorize",
        tenant_id="t1",
        payload={},
        fail_closed=False,
    )
    assert report.errors
    assert report.errors[0].classification == HookErrorClass.TIMEOUT

