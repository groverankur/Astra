from dataclasses import dataclass
from typing import Any

from astraauth_plugins import GeoPlugin
from fastapi import FastAPI
from fastapi.testclient import TestClient

from astraauth.adapters.extensions import mount_plugin_endpoints_fastapi
from astraauth.plugins import PluginRuntime
from astraauth.plugins.contracts import ColumnExtension, EndpointExtension, HookName, TableExtension


def test_mount_plugin_endpoints_fastapi() -> None:
    app = FastAPI()
    runtime = PluginRuntime()
    runtime.register(GeoPlugin())
    runtime.enable_for_tenant(tenant_id="Default", plugin_name="geo")

    mount_plugin_endpoints_fastapi(app=app, runtime=runtime, tenant_id="Default")

    client = TestClient(app)
    resp = client.get("/auth/ext/geo/health")
    assert resp.status_code == 200
    assert resp.json()["plugin"] == "geo"
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["referrer-policy"] == "no-referrer"
    assert resp.headers["cache-control"] == "no-store"


@dataclass
class FailingEndpointPlugin:
    name: str = "bad"
    order: int = 1

    def hooks(self) -> dict[HookName, Any]:
        return {}

    def register_endpoints(self) -> tuple[EndpointExtension, ...]:
        return (EndpointExtension(self.name, "/auth/ext/bad/fail", ("GET",), self._fail),)

    def register_tables(self) -> tuple[TableExtension, ...]:
        return ()

    def register_columns(self) -> tuple[ColumnExtension, ...]:
        return ()

    def _fail(self, payload: dict[str, Any]) -> dict[str, Any]:
        raise ValueError("bad payload")


def test_mount_plugin_endpoints_fastapi_masks_plugin_failures() -> None:
    app = FastAPI()
    runtime = PluginRuntime()
    runtime.register(FailingEndpointPlugin())
    runtime.enable_for_tenant(tenant_id="Default", plugin_name="bad")

    mount_plugin_endpoints_fastapi(app=app, runtime=runtime, tenant_id="Default")

    client = TestClient(app)
    resp = client.get("/auth/ext/bad/fail")
    assert resp.status_code == 400
    assert resp.json()["error"] == "plugin_endpoint_invalid"
    audit = runtime.audit_records()
    assert audit[-1].execution_type == "endpoint"
    assert audit[-1].status == "failed"
