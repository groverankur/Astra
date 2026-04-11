from astraauth_adapters.extensions import mount_plugin_endpoints_fastapi
from astraauth_plugins import GeoPlugin, PluginRuntime
from fastapi import FastAPI
from fastapi.testclient import TestClient


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
