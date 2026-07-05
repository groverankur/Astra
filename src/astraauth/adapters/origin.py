from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from astraauth.core.adapters.http_types import HttpResponse, NormalizedRequestContext

_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


@dataclass(frozen=True)
class AdapterOriginPolicy:
    allowed_origins: frozenset[str] = frozenset()
    allowed_callback_origins: frozenset[str] = frozenset()
    allow_credentials: bool = True
    allowed_headers: tuple[str, ...] = ("authorization", "content-type", "x-correlation-id")
    allowed_methods: tuple[str, ...] = ("GET", "POST", "OPTIONS")

    def allowed_for_request(self, request: NormalizedRequestContext) -> frozenset[str]:
        if request.request_path == "/oidc/callback":
            return self.allowed_callback_origins or self.allowed_origins
        return self.allowed_origins


def reject_disallowed_origin(
    request: NormalizedRequestContext,
    *,
    policy: AdapterOriginPolicy | None,
) -> HttpResponse | None:
    active_policy = policy or AdapterOriginPolicy()
    origin = request.header("origin")
    if not origin:
        return None
    if request.http_method.upper() not in _UNSAFE_METHODS:
        return None
    if origin in active_policy.allowed_for_request(request):
        return None
    return HttpResponse(
        status=403,
        body={
            "error": "origin_not_allowed",
            "error_description": "Cross-origin state-changing requests are not allowed from this origin.",
        },
    )


def preflight_response(
    request: NormalizedRequestContext,
    *,
    policy: AdapterOriginPolicy | None,
) -> HttpResponse:
    active_policy = policy or AdapterOriginPolicy()
    origin = request.header("origin")
    requested_method = request.header("access-control-request-method")
    if not origin or not requested_method:
        return HttpResponse(status=400, body={"error": "invalid_cors_preflight"})
    requested = requested_method.upper()
    if requested in _UNSAFE_METHODS and origin not in active_policy.allowed_for_request(request):
        return HttpResponse(status=403, body={"error": "origin_not_allowed"})
    return apply_origin_headers(
        request,
        HttpResponse(status=204, body=None),
        policy=active_policy,
        preflight=True,
    )


def apply_origin_headers(
    request: NormalizedRequestContext,
    response: HttpResponse,
    *,
    policy: AdapterOriginPolicy | None,
    preflight: bool = False,
) -> HttpResponse:
    active_policy = policy or AdapterOriginPolicy()
    origin = request.header("origin")
    if not origin or origin not in active_policy.allowed_for_request(request):
        return response
    headers = dict(response.headers or {})
    headers["Access-Control-Allow-Origin"] = origin
    headers["Vary"] = _append_vary(headers.get("Vary"), "Origin")
    if active_policy.allow_credentials:
        headers["Access-Control-Allow-Credentials"] = "true"
    if preflight:
        headers["Access-Control-Allow-Methods"] = ", ".join(active_policy.allowed_methods)
        headers["Access-Control-Allow-Headers"] = ", ".join(active_policy.allowed_headers)
        headers["Access-Control-Max-Age"] = "600"
    return HttpResponse(status=response.status, body=response.body, headers=headers)


def call_with_origin_policy(
    request: NormalizedRequestContext,
    handler: Callable[[NormalizedRequestContext], HttpResponse],
    *,
    policy: AdapterOriginPolicy | None,
) -> HttpResponse:
    rejected = reject_disallowed_origin(request, policy=policy)
    if rejected is not None:
        return apply_origin_headers(request, rejected, policy=policy)
    return apply_origin_headers(request, handler(request), policy=policy)


def _append_vary(current: str | None, value: str) -> str:
    if not current:
        return value
    parts = {part.strip().lower() for part in current.split(",")}
    if value.lower() in parts:
        return current
    return f"{current}, {value}"
