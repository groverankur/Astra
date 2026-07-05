from dataclasses import dataclass
from typing import Any

from astraauth.core.adapters.http_types import NormalizedRequestContext
from astraauth.plugins.contracts import ColumnExtension, EndpointExtension, HookName, TableExtension
from astraauth.service import build_inmemory_service


@dataclass
class BlockingPlugin:
    name: str = "blocking"
    order: int = 1

    def hooks(self) -> dict[HookName, Any]:
        return {"auth.pre_authorize": self._block}

    def register_endpoints(self) -> tuple[EndpointExtension, ...]:
        return ()

    def register_tables(self) -> tuple[TableExtension, ...]:
        return ()

    def register_columns(self) -> tuple[ColumnExtension, ...]:
        return ()

    def _block(self, payload: dict[str, Any]) -> dict[str, Any]:
        raise ValueError("blocked by policy")


def test_pre_authorize_plugin_can_fail_closed_request() -> None:
    svc = build_inmemory_service(default_plugins_enabled=False)
    svc.register_plugin(BlockingPlugin())
    svc.enable_plugin(tenant_id="Default", plugin_name="blocking")

    req = NormalizedRequestContext(
        http_method="POST",
        request_path="/token",
        query_params={},
        headers={},
        form_data={
            "grant_type": "refresh_token",
            "client_id": "c1",
            "tenant_id": "Default",
            "refresh_token": "dummy",
        },
    )

    resp = svc.adapter.handle_token(req)
    assert resp.status == 403
    assert isinstance(resp.body, dict)
    assert resp.body["error"] == "access_denied"


def test_default_plugins_are_available_on_service_bootstrap() -> None:
    svc = build_inmemory_service(default_plugins_enabled=True)
    enabled = svc.plugin_runtime.tenant_plugins()
    assert set(enabled.get("Default", ())) == {"geo", "risk"}
