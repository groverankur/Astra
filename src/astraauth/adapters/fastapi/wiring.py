from collections.abc import Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from astraauth.adapters.origin import (
    AdapterOriginPolicy,
    call_with_origin_policy,
    preflight_response,
)
from astraauth.core.adapters.http_types import HttpResponse, NormalizedRequestContext
from astraauth.core.adapters.oauth_http import OAuthHTTPAdapter
from astraauth.core.adapters.security_headers import apply_runtime_security_headers


def _form_request(req: Request, form_data: dict[str, str]) -> NormalizedRequestContext:
    return NormalizedRequestContext(
        http_method=req.method,
        request_path=str(req.url.path),
        query_params=dict(req.query_params),
        headers=dict(req.headers),
        form_data=form_data,
        cookies=req.cookies,
        client_ip=req.client.host if req.client else None,
        body_json=None,
    )


def _json_response(resp: HttpResponse, *, allow_caching: bool = False) -> Response:
    resp = apply_runtime_security_headers(resp, allow_caching=allow_caching)
    if resp.status == 302 and resp.headers:
        headers = dict(resp.headers)
        location = headers.pop("Location")
        return RedirectResponse(location, status_code=302, headers=headers)
    return JSONResponse(content=resp.body, status_code=resp.status, headers=resp.headers or {})


def _origin_response(req: Request, policy: AdapterOriginPolicy | None) -> Response:
    return _json_response(preflight_response(_form_request(req, {}), policy=policy))


def mount_oauth(  # noqa: C901
    app: FastAPI,
    adapter: OAuthHTTPAdapter,
    *,
    origin_policy: AdapterOriginPolicy | None = None,
) -> None:
    def _call(
        req: Request,
        handler: Callable[[NormalizedRequestContext], HttpResponse],
        form_data: dict[str, str],
        *,
        allow_caching: bool = False,
    ) -> Response:
        request = _form_request(req, form_data)
        response = call_with_origin_policy(request, handler, policy=origin_policy)
        return _json_response(response, allow_caching=allow_caching)

    @app.options("/{path:path}")
    async def cors_preflight(req: Request) -> Response:
        return _origin_response(req, origin_policy)

    @app.get("/authorize")
    async def authorize(req: Request) -> Response:
        return _call(req, adapter.handle_authorize, {})

    @app.post("/token")
    async def token(req: Request) -> Response:
        form = await req.form()
        return _call(
            req, adapter.handle_token, {k: v for k, v in form.items() if isinstance(v, str)}
        )

    @app.post("/logout")
    async def logout(req: Request) -> Response:
        form = await req.form()
        return _call(
            req, adapter.handle_logout, {k: v for k, v in form.items() if isinstance(v, str)}
        )

    @app.post("/introspect")
    async def introspect(req: Request) -> Response:
        form = await req.form()
        return _call(
            req, adapter.handle_introspect, {k: v for k, v in form.items() if isinstance(v, str)}
        )

    @app.post("/mfa/challenge")
    async def mfa_challenge(req: Request) -> Response:
        form = await req.form()
        return _call(
            req, adapter.handle_mfa_challenge, {k: v for k, v in form.items() if isinstance(v, str)}
        )

    @app.post("/mfa/verify")
    async def mfa_verify(req: Request) -> Response:
        form = await req.form()
        return _call(
            req, adapter.handle_mfa_verify, {k: v for k, v in form.items() if isinstance(v, str)}
        )

    @app.post("/webauthn/register/start")
    async def webauthn_register_start(req: Request) -> Response:
        form = await req.form()
        return _call(
            req,
            adapter.handle_webauthn_register_start,
            {k: v for k, v in form.items() if isinstance(v, str)},
        )

    @app.post("/webauthn/register/finish")
    async def webauthn_register_finish(req: Request) -> Response:
        form = await req.form()
        return _call(
            req,
            adapter.handle_webauthn_register_finish,
            {k: v for k, v in form.items() if isinstance(v, str)},
        )

    @app.post("/webauthn/authenticate/start")
    async def webauthn_authenticate_start(req: Request) -> Response:
        form = await req.form()
        return _call(
            req,
            adapter.handle_webauthn_authenticate_start,
            {k: v for k, v in form.items() if isinstance(v, str)},
        )

    @app.post("/webauthn/authenticate/finish")
    async def webauthn_authenticate_finish(req: Request) -> Response:
        form = await req.form()
        return _call(
            req,
            adapter.handle_webauthn_authenticate_finish,
            {k: v for k, v in form.items() if isinstance(v, str)},
        )

    @app.post("/oidc/login/start")
    async def oidc_login_start(req: Request) -> Response:
        form = await req.form()
        return _call(
            req,
            adapter.handle_oidc_login_start,
            {k: v for k, v in form.items() if isinstance(v, str)},
        )

    @app.get("/oidc/callback")
    async def oidc_callback(req: Request) -> Response:
        return _call(req, adapter.handle_oidc_callback, {})

    @app.get("/.well-known/jwks.json")
    async def jwks(req: Request) -> Response:
        return _call(req, adapter.handle_jwks, {}, allow_caching=True)

    @app.get("/.well-known/openid-configuration")
    async def oidc_conf() -> Response:
        return _json_response(
            adapter.handle_openid_configuration(issuer="https://auth.local"),
            allow_caching=True,
        )
