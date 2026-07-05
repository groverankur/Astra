from __future__ import annotations

import contextvars
from typing import Any

_CURRENT_TENANT = contextvars.ContextVar[str | None]("current_tenant", default=None)


def get_current_tenant() -> str | None:
    return _CURRENT_TENANT.get()


def set_current_tenant(tenant_id: str | None) -> contextvars.Token[str | None]:
    return _CURRENT_TENANT.set(tenant_id)


def reset_current_tenant(token: contextvars.Token[str | None]) -> None:
    _CURRENT_TENANT.reset(token)


class ASGITenancyMiddleware:
    def __init__(self, app: Any, header_name: str = "X-Tenant-ID"):
        self.app = app
        self.header_name = header_name.lower().encode("utf-8")

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        tenant_id = None
        for key, value in scope.get("headers", []):
            if key == self.header_name:
                tenant_id = value.decode("utf-8")
                break

        token = set_current_tenant(tenant_id)
        try:
            await self.app(scope, receive, send)
        finally:
            reset_current_tenant(token)


def mount_flask_tenancy_routing(app: Any, header_name: str = "X-Tenant-ID") -> None:
    @app.before_request
    def bind_tenant_context() -> None:
        from flask import request

        tenant_id = request.headers.get(header_name)
        request.environ["_tenant_token"] = set_current_tenant(tenant_id)

    @app.after_request
    def unbind_tenant_context(response: Any) -> Any:
        from flask import request

        token = request.environ.get("_tenant_token")
        if token:
            reset_current_tenant(token)
        return response
