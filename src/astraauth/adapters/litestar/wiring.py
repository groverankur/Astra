import json
from collections.abc import Callable
from typing import Any

from litestar import Litestar, Request, Response, get, post, route

from astraauth.adapters.origin import (
    AdapterOriginPolicy,
    call_with_origin_policy,
    preflight_response,
)
from astraauth.core.adapters.http_types import HttpResponse, NormalizedRequestContext
from astraauth.core.adapters.oauth_http import OAuthHTTPAdapter
from astraauth.core.adapters.security_headers import apply_runtime_security_headers


def _request(
    request: Request[Any, Any, Any], form_data: dict[str, str]
) -> NormalizedRequestContext:
    return NormalizedRequestContext(
        http_method=request.method,
        request_path=str(request.url.path),
        query_params=dict(request.query_params),
        headers=dict(request.headers),
        form_data=form_data,
        cookies=request.cookies,
        client_ip=request.client.host if request.client else None,
        body_json=None,
    )


def _response(resp: HttpResponse, *, allow_caching: bool = False) -> Response[str]:
    resp = apply_runtime_security_headers(resp, allow_caching=allow_caching)
    body_content = json.dumps(resp.body) if isinstance(resp.body, dict) else (resp.body or "")
    return Response(content=body_content, status_code=resp.status, headers=resp.headers or {})


def mount_oauth(  # noqa: C901
    app: Litestar,
    adapter: OAuthHTTPAdapter,
    *,
    origin_policy: AdapterOriginPolicy | None = None,
) -> None:
    def _call(
        request: Request[Any, Any, Any],
        handler: Callable[[NormalizedRequestContext], HttpResponse],
        form_data: dict[str, str],
        *,
        allow_caching: bool = False,
    ) -> Response[str]:
        req = _request(request, form_data)
        return _response(
            call_with_origin_policy(req, handler, policy=origin_policy),
            allow_caching=allow_caching,
        )

    @route("/{path:path}", http_method=["OPTIONS"])
    async def cors_preflight(request: Request[Any, Any, Any]) -> Response[str]:
        return _response(preflight_response(_request(request, {}), policy=origin_policy))

    @get("/authorize")
    async def authorize(request: Request[Any, Any, Any]) -> Response[str]:
        resp = call_with_origin_policy(
            _request(request, {}), adapter.handle_authorize, policy=origin_policy
        )
        if resp.status == 302:
            return Response(content="", status_code=302, headers=resp.headers)
        return _response(resp)

    @post("/token")
    async def token(request: Request[Any, Any, Any]) -> Response[str]:
        form = await request.form()
        return _call(
            request,
            adapter.handle_token,
            {k: v for k, v in dict(form).items() if isinstance(v, str)},
        )

    @post("/logout")
    async def logout(request: Request[Any, Any, Any]) -> Response[str]:
        form = await request.form()
        return _call(
            request,
            adapter.handle_logout,
            {k: v for k, v in dict(form).items() if isinstance(v, str)},
        )

    @post("/introspect")
    async def introspect(request: Request[Any, Any, Any]) -> Response[str]:
        form = await request.form()
        return _call(
            request,
            adapter.handle_introspect,
            {k: v for k, v in dict(form).items() if isinstance(v, str)},
        )

    @post("/mfa/challenge")
    async def mfa_challenge(request: Request[Any, Any, Any]) -> Response[str]:
        form = await request.form()
        return _call(
            request,
            adapter.handle_mfa_challenge,
            {k: v for k, v in dict(form).items() if isinstance(v, str)},
        )

    @post("/mfa/verify")
    async def mfa_verify(request: Request[Any, Any, Any]) -> Response[str]:
        form = await request.form()
        return _call(
            request,
            adapter.handle_mfa_verify,
            {k: v for k, v in dict(form).items() if isinstance(v, str)},
        )

    @post("/webauthn/register/start")
    async def webauthn_register_start(request: Request[Any, Any, Any]) -> Response[str]:
        form = await request.form()
        return _call(
            request,
            adapter.handle_webauthn_register_start,
            {k: v for k, v in dict(form).items() if isinstance(v, str)},
        )

    @post("/webauthn/register/finish")
    async def webauthn_register_finish(request: Request[Any, Any, Any]) -> Response[str]:
        form = await request.form()
        return _call(
            request,
            adapter.handle_webauthn_register_finish,
            {k: v for k, v in dict(form).items() if isinstance(v, str)},
        )

    @post("/webauthn/authenticate/start")
    async def webauthn_authenticate_start(request: Request[Any, Any, Any]) -> Response[str]:
        form = await request.form()
        return _call(
            request,
            adapter.handle_webauthn_authenticate_start,
            {k: v for k, v in dict(form).items() if isinstance(v, str)},
        )

    @post("/webauthn/authenticate/finish")
    async def webauthn_authenticate_finish(request: Request[Any, Any, Any]) -> Response[str]:
        form = await request.form()
        return _call(
            request,
            adapter.handle_webauthn_authenticate_finish,
            {k: v for k, v in dict(form).items() if isinstance(v, str)},
        )

    @post("/oidc/login/start")
    async def oidc_login_start(request: Request[Any, Any, Any]) -> Response[str]:
        form = await request.form()
        resp = call_with_origin_policy(
            _request(request, {k: v for k, v in dict(form).items() if isinstance(v, str)}),
            adapter.handle_oidc_login_start,
            policy=origin_policy,
        )
        if resp.status == 302:
            return Response(content="", status_code=302, headers=resp.headers)
        return _response(resp)

    @get("/oidc/callback")
    async def oidc_callback(request: Request[Any, Any, Any]) -> Response[str]:
        return _call(request, adapter.handle_oidc_callback, {})

    @get("/.well-known/jwks.json")
    async def jwks(request: Request[Any, Any, Any]) -> Response[str]:
        return _call(request, adapter.handle_jwks, {}, allow_caching=True)

    @get("/.well-known/openid-configuration")
    async def oidc_conf() -> Response[str]:
        return _response(
            adapter.handle_openid_configuration(issuer="https://auth.local"), allow_caching=True
        )
