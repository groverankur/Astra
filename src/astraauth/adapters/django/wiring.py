from __future__ import annotations

from typing import Any

from astraauth.adapters.origin import (
    AdapterOriginPolicy,
    call_with_origin_policy,
    preflight_response,
)
from astraauth.core.adapters.http_types import HttpResponse, NormalizedRequestContext
from astraauth.core.adapters.oauth_http import OAuthHTTPAdapter
from astraauth.core.adapters.security_headers import apply_runtime_security_headers


def _request_context(request: Any) -> NormalizedRequestContext:
    try:
        body_json = request.json()
    except Exception:
        body_json = None
    return NormalizedRequestContext(
        http_method=str(request.method),
        request_path=str(request.path),
        query_params=dict(request.GET.items()),
        headers={str(key): str(value) for key, value in request.headers.items()},
        form_data=dict(request.POST.items()),
        cookies=dict(request.COOKIES.items()),
        client_ip=request.META.get("REMOTE_ADDR"),
        body_json=body_json,
    )


def _to_django_response(response: HttpResponse, *, allow_caching: bool = False) -> Any:
    from django.http import HttpResponse as DjangoHttpResponse
    from django.http import JsonResponse
    from django.shortcuts import redirect

    response = apply_runtime_security_headers(response, allow_caching=allow_caching)
    if response.status == 302 and response.headers and "Location" in response.headers:
        headers = dict(response.headers)
        django_response = redirect(headers.pop("Location"))
        for key, value in headers.items():
            django_response[key] = value
        return django_response
    if response.body is None:
        django_response = DjangoHttpResponse(status=response.status)
        for key, value in (response.headers or {}).items():
            django_response[key] = value
        return django_response
    payload = response.body if isinstance(response.body, dict) else {"body": response.body}
    django_response = JsonResponse(payload)
    django_response.status_code = response.status
    for key, value in (response.headers or {}).items():
        django_response[key] = value
    return django_response


def _make_handler(
    adapter: OAuthHTTPAdapter,
    handler_name: str,
    *,
    origin_policy: AdapterOriginPolicy | None,
) -> Any:
    def handler(request: Any) -> Any:
        adapter_handler = getattr(adapter, handler_name)
        req = _request_context(request)
        return _to_django_response(
            call_with_origin_policy(req, adapter_handler, policy=origin_policy),
            allow_caching=handler_name == "handle_jwks",
        )

    return handler


def build_urlpatterns(
    *,
    adapter: OAuthHTTPAdapter,
    issuer: str = "https://auth.local",
    origin_policy: AdapterOriginPolicy | None = None,
) -> list[Any]:
    from django.urls import path

    route_handlers = [
        ("authorize", "handle_authorize"),
        ("token", "handle_token"),
        ("logout", "handle_logout"),
        ("introspect", "handle_introspect"),
        ("mfa/challenge", "handle_mfa_challenge"),
        ("mfa/verify", "handle_mfa_verify"),
        ("webauthn/register/start", "handle_webauthn_register_start"),
        ("webauthn/register/finish", "handle_webauthn_register_finish"),
        ("webauthn/authenticate/start", "handle_webauthn_authenticate_start"),
        ("webauthn/authenticate/finish", "handle_webauthn_authenticate_finish"),
        ("oidc/login/start", "handle_oidc_login_start"),
        ("oidc/callback", "handle_oidc_callback"),
        (".well-known/jwks.json", "handle_jwks"),
    ]

    def openid_configuration(request: Any) -> Any:
        _ = request
        return _to_django_response(
            adapter.handle_openid_configuration(issuer=issuer),
            allow_caching=True,
        )

    def cors_preflight(request: Any, route: str = "") -> Any:
        _ = route
        return _to_django_response(
            preflight_response(_request_context(request), policy=origin_policy)
        )

    urlpatterns = [
        path(route, _make_handler(adapter, handler_name, origin_policy=origin_policy))
        for route, handler_name in route_handlers
    ]
    urlpatterns.append(path(".well-known/openid-configuration", openid_configuration))
    urlpatterns.append(path("<path:route>", cors_preflight))
    return urlpatterns
