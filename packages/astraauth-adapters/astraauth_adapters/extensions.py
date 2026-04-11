from __future__ import annotations

from typing import Any, cast

from astraauth_plugins.runtime import PluginRuntime
from fastapi import Request as FastAPIRequest


def _build_payload(
    *,
    method: str,
    path: str,
    query: dict[str, str],
    headers: dict[str, str],
    form: dict[str, str] | None = None,
    json_body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "method": method,
        "path": path,
        "query": query,
        "headers": headers,
        "form": form or {},
        "json": json_body,
    }


def mount_plugin_endpoints_fastapi(
    *,
    app: Any,
    runtime: PluginRuntime,
    tenant_id: str = "Default",
) -> None:
    from fastapi.responses import JSONResponse, PlainTextResponse, Response

    def _build_fastapi_handler(extension: Any) -> Any:
        async def _handler(request: FastAPIRequest) -> Response:
            try:
                body_json = await request.json()
                if not isinstance(body_json, dict):
                    body_json = None
            except Exception:
                body_json = None

            payload = _build_payload(
                method=request.method,
                path=str(request.url.path),
                query=dict(request.query_params),
                headers=dict(request.headers),
                json_body=body_json,
            )
            result = extension.handler(payload)
            if result is None:
                return JSONResponse({"status": "ok"})
            if isinstance(result, dict):
                return JSONResponse(result)
            return PlainTextResponse(str(result))

        return _handler

    for ext in runtime.endpoint_extensions(tenant_id=tenant_id):
        for method in ext.methods:
            method_upper = method.upper()
            app.add_api_route(ext.path, _build_fastapi_handler(ext), methods=[method_upper])


def mount_plugin_endpoints_litestar(
    *,
    app: Any,
    runtime: PluginRuntime,
    tenant_id: str = "Default",
) -> None:
    import json

    from litestar import Request, Response, route

    for ext in runtime.endpoint_extensions(tenant_id=tenant_id):
        methods = [m.upper() for m in ext.methods]

        def _build_litestar_handler(
            extension: Any, *, path: str, methods_for_route: list[str]
        ) -> Any:
            @route(path, http_method=cast(Any, methods_for_route))
            async def _handler(request: Request[Any, Any, Any]) -> Response[str]:
                payload = _build_payload(
                    method=request.method,
                    path=str(request.url.path),
                    query=dict(request.query_params),
                    headers=dict(request.headers),
                    json_body=None,
                )
                result = extension.handler(payload)
                if result is None:
                    return Response(content='{"status":"ok"}', media_type="application/json")
                if isinstance(result, dict):
                    return Response(content=json.dumps(result), media_type="application/json")
                return Response(content=str(result), media_type="text/plain")

            return _handler

        app.register(_build_litestar_handler(ext, path=ext.path, methods_for_route=methods))


def mount_plugin_endpoints_robyn(
    *,
    app: Any,
    runtime: PluginRuntime,
    tenant_id: str = "Default",
) -> None:
    from robyn import Request, Response

    def _build_robyn_handler(extension: Any, method_value: str) -> Any:
        async def _handler(request: Request) -> Response:
            payload = _build_payload(
                method=method_value.upper(),
                path=request.url.path,
                query=request.query_params,
                headers=request.headers,
                json_body=None,
            )
            result = extension.handler(payload)
            if result is None:
                return Response(json={"status": "ok"}, status_code=200)
            if isinstance(result, dict):
                return Response(json=result, status_code=200)
            return Response(description=str(result), status_code=200)

        return _handler

    for ext in runtime.endpoint_extensions(tenant_id=tenant_id):
        for method in ext.methods:
            method_lower = method.lower()
            decorator = getattr(app, method_lower)
            decorator(ext.path)(_build_robyn_handler(ext, method))
