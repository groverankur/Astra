from collections.abc import Callable
from typing import Any

import pytest
from astraauth_tenancy import (
    ASGITenancyMiddleware,
    get_current_tenant,
    mount_flask_tenancy_routing,
)


@pytest.mark.asyncio
async def test_asgi_tenancy_middleware() -> None:
    # 1. Setup mock ASGI application
    async def mock_app(
        scope: dict, receive: Callable[[], Any], send: Callable[[dict], Any]
    ) -> None:
        # Assert within request flow that tenant is bound
        assert get_current_tenant() == "tenant-x"
        await send({"type": "http.response.start", "status": 200})

    # Wrap in middleware
    middleware = ASGITenancyMiddleware(mock_app, header_name="X-Tenant-ID")

    # Mock ASGI request components
    scope = {
        "type": "http",
        "headers": [
            (b"x-tenant-id", b"tenant-x"),
        ],
    }

    async def mock_receive() -> dict:
        return {}

    async def mock_send(event: dict) -> None:
        _ = event

    # Execute request call
    await middleware(scope, mock_receive, mock_send)

    # Assert context is cleared after request finishes
    assert get_current_tenant() is None


def test_flask_tenancy_middleware() -> None:
    # 1. Import Flask locally
    pytest.importorskip("flask")
    from flask import Flask

    # 2. Build mock app and mount tenancy helper
    app = Flask("test_app")
    mount_flask_tenancy_routing(app, header_name="X-Tenant-ID")

    @app.route("/")
    def index() -> str:
        # Context variable should be bound
        return f"active-tenant:{get_current_tenant()}"

    with app.test_client() as client:
        # Test call passing tenant ID header
        resp = client.get("/", headers={"X-Tenant-ID": "tenant-y"})
        assert resp.status_code == 200
        assert resp.data.decode("utf-8") == "active-tenant:tenant-y"

    # Context should be unbound outside active request cycle
    assert get_current_tenant() is None
