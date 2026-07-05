from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from fastapi import Request as FastAPIRequest

from astraauth.core.adapters.http_types import HttpResponse
from astraauth.core.adapters.security_headers import apply_runtime_security_headers
from astraauth.plugins.contracts import EndpointExecutionReport, HookErrorClass
from astraauth.plugins.runtime import PluginRuntime


def _build_payload(
    *,
    method: str,
    path: str,
    query: Mapping[str, str],
    headers: Mapping[str, str],
    form: Mapping[str, str] | None = None,
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


def _secure_headers(
    headers: Mapping[str, str] | None = None,
    *,
    allow_caching: bool = False,
) -> dict[str, str]:
    secured = apply_runtime_security_headers(
        HttpResponse(status=200, body="", headers=dict(headers or {})),
        allow_caching=allow_caching,
    )
    return dict(secured.headers or {})


def _endpoint_error_payload(report: EndpointExecutionReport) -> tuple[int, dict[str, Any]]:
    classification = report.errors[0].classification if report.errors else HookErrorClass.RUNTIME
    if classification == HookErrorClass.TIMEOUT:
        return 504, {"error": "plugin_endpoint_timeout"}
    if classification == HookErrorClass.VALIDATION:
        return 400, {"error": "plugin_endpoint_invalid"}
    return 500, {"error": "plugin_endpoint_failed"}


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
            report = runtime.invoke_endpoint(
                tenant_id=tenant_id,
                extension=extension,
                payload=payload,
                fail_closed=False,
            )
            if report.errors:
                status, error_body = _endpoint_error_payload(report)
                return JSONResponse(error_body, status_code=status, headers=_secure_headers())
            result = report.result
            if result is None:
                return JSONResponse({"status": "ok"}, headers=_secure_headers())
            if isinstance(result, dict):
                return JSONResponse(result, headers=_secure_headers())
            return PlainTextResponse(str(result), headers=_secure_headers())

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
                report = runtime.invoke_endpoint(
                    tenant_id=tenant_id,
                    extension=extension,
                    payload=payload,
                    fail_closed=False,
                )
                if report.errors:
                    status, error_body = _endpoint_error_payload(report)
                    return Response(
                        content=json.dumps(error_body),
                        status_code=status,
                        media_type="application/json",
                        headers=_secure_headers(),
                    )
                result = report.result
                if result is None:
                    return Response(
                        content='{"status":"ok"}',
                        media_type="application/json",
                        headers=_secure_headers(),
                    )
                if isinstance(result, dict):
                    return Response(
                        content=json.dumps(result),
                        media_type="application/json",
                        headers=_secure_headers(),
                    )
                return Response(
                    content=str(result),
                    media_type="text/plain",
                    headers=_secure_headers(),
                )

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
                query={
                    str(key): str(value)
                    for key, value in cast(dict[str, str], request.query_params).items()
                },
                headers={
                    str(key): str(value)
                    for key, value in cast(dict[str, str], request.headers).items()
                },
                json_body=None,
            )
            report = runtime.invoke_endpoint(
                tenant_id=tenant_id,
                extension=extension,
                payload=payload,
                fail_closed=False,
            )
            if report.errors:
                status, error_body = _endpoint_error_payload(report)
                import json

                return Response(status, _secure_headers(), json.dumps(error_body))
            result = report.result
            headers = _secure_headers()
            if result is None:
                return Response(200, headers, '{"status": "ok"}')
            if isinstance(result, dict):
                import json

                return Response(200, headers, json.dumps(result))
            return Response(200, headers, str(result))

        return _handler

    for ext in runtime.endpoint_extensions(tenant_id=tenant_id):
        for method in ext.methods:
            method_lower = method.lower()
            decorator = getattr(app, method_lower)
            decorator(ext.path)(_build_robyn_handler(ext, method))
