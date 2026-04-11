import json
from typing import Any

from astraauth_core.adapters.http_types import HttpResponse, NormalizedRequestContext
from astraauth_core.adapters.oauth_http import OAuthHTTPAdapter
from litestar import Litestar, Request, Response, get, post


def _request(request: Request[Any, Any, Any], form_data: dict[str, str]) -> NormalizedRequestContext:
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


def _response(resp: HttpResponse) -> Response[str]:
    body_content = json.dumps(resp.body) if isinstance(resp.body, dict) else (resp.body or "")
    return Response(content=body_content, status_code=resp.status, headers=resp.headers or {})


def mount_oauth(app: Litestar, adapter: OAuthHTTPAdapter) -> None:  # noqa: C901
    @get("/authorize")
    async def authorize(request: Request[Any, Any, Any]) -> Response[str]:
        resp = adapter.handle_authorize(_request(request, {}))
        if resp.status == 302:
            return Response(content="", status_code=302, headers=resp.headers)
        return _response(resp)

    @post("/token")
    async def token(request: Request[Any, Any, Any]) -> Response[str]:
        form = await request.form()
        return _response(adapter.handle_token(_request(request, {k: v for k, v in dict(form).items() if isinstance(v, str)})))

    @post("/logout")
    async def logout(request: Request[Any, Any, Any]) -> Response[str]:
        form = await request.form()
        return _response(adapter.handle_logout(_request(request, {k: v for k, v in dict(form).items() if isinstance(v, str)})))

    @post("/introspect")
    async def introspect(request: Request[Any, Any, Any]) -> Response[str]:
        form = await request.form()
        return _response(adapter.handle_introspect(_request(request, {k: v for k, v in dict(form).items() if isinstance(v, str)})))

    @post("/mfa/challenge")
    async def mfa_challenge(request: Request[Any, Any, Any]) -> Response[str]:
        form = await request.form()
        return _response(adapter.handle_mfa_challenge(_request(request, {k: v for k, v in dict(form).items() if isinstance(v, str)})))

    @post("/mfa/verify")
    async def mfa_verify(request: Request[Any, Any, Any]) -> Response[str]:
        form = await request.form()
        return _response(adapter.handle_mfa_verify(_request(request, {k: v for k, v in dict(form).items() if isinstance(v, str)})))

    @post("/webauthn/register/start")
    async def webauthn_register_start(request: Request[Any, Any, Any]) -> Response[str]:
        form = await request.form()
        return _response(adapter.handle_webauthn_register_start(_request(request, {k: v for k, v in dict(form).items() if isinstance(v, str)})))

    @post("/webauthn/register/finish")
    async def webauthn_register_finish(request: Request[Any, Any, Any]) -> Response[str]:
        form = await request.form()
        return _response(adapter.handle_webauthn_register_finish(_request(request, {k: v for k, v in dict(form).items() if isinstance(v, str)})))

    @post("/webauthn/authenticate/start")
    async def webauthn_authenticate_start(request: Request[Any, Any, Any]) -> Response[str]:
        form = await request.form()
        return _response(adapter.handle_webauthn_authenticate_start(_request(request, {k: v for k, v in dict(form).items() if isinstance(v, str)})))

    @post("/webauthn/authenticate/finish")
    async def webauthn_authenticate_finish(request: Request[Any, Any, Any]) -> Response[str]:
        form = await request.form()
        return _response(adapter.handle_webauthn_authenticate_finish(_request(request, {k: v for k, v in dict(form).items() if isinstance(v, str)})))

    @post("/oidc/login/start")
    async def oidc_login_start(request: Request[Any, Any, Any]) -> Response[str]:
        form = await request.form()
        resp = adapter.handle_oidc_login_start(_request(request, {k: v for k, v in dict(form).items() if isinstance(v, str)}))
        if resp.status == 302:
            return Response(content="", status_code=302, headers=resp.headers)
        return _response(resp)

    @get("/oidc/callback")
    async def oidc_callback(request: Request[Any, Any, Any]) -> Response[str]:
        return _response(adapter.handle_oidc_callback(_request(request, {})))

    @get("/.well-known/jwks.json")
    async def jwks(request: Request[Any, Any, Any]) -> Response[str]:
        return _response(adapter.handle_jwks(_request(request, {})))

    @get("/.well-known/openid-configuration")
    async def oidc_conf() -> Response[str]:
        return _response(adapter.handle_openid_configuration(issuer="https://auth.local"))

