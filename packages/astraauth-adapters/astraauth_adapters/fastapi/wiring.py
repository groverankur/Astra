from astraauth_core.adapters.http_types import HttpResponse, NormalizedRequestContext
from astraauth_core.adapters.oauth_http import OAuthHTTPAdapter
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response


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


def _json_response(resp: HttpResponse) -> Response:
    if resp.status == 302 and resp.headers:
        headers = dict(resp.headers)
        location = headers.pop("Location")
        return RedirectResponse(location, status_code=302, headers=headers)
    return JSONResponse(content=resp.body, status_code=resp.status, headers=resp.headers or {})


def mount_oauth(app: FastAPI, adapter: OAuthHTTPAdapter) -> None:  # noqa: C901
    @app.get("/authorize")
    async def authorize(req: Request) -> Response:
        return _json_response(adapter.handle_authorize(_form_request(req, {})))

    @app.post("/token")
    async def token(req: Request) -> Response:
        form = await req.form()
        return _json_response(adapter.handle_token(_form_request(req, {k: v for k, v in form.items() if isinstance(v, str)})))

    @app.post("/logout")
    async def logout(req: Request) -> Response:
        form = await req.form()
        return _json_response(adapter.handle_logout(_form_request(req, {k: v for k, v in form.items() if isinstance(v, str)})))

    @app.post("/introspect")
    async def introspect(req: Request) -> Response:
        form = await req.form()
        return _json_response(adapter.handle_introspect(_form_request(req, {k: v for k, v in form.items() if isinstance(v, str)})))

    @app.post("/mfa/challenge")
    async def mfa_challenge(req: Request) -> Response:
        form = await req.form()
        return _json_response(adapter.handle_mfa_challenge(_form_request(req, {k: v for k, v in form.items() if isinstance(v, str)})))

    @app.post("/mfa/verify")
    async def mfa_verify(req: Request) -> Response:
        form = await req.form()
        return _json_response(adapter.handle_mfa_verify(_form_request(req, {k: v for k, v in form.items() if isinstance(v, str)})))

    @app.post("/webauthn/register/start")
    async def webauthn_register_start(req: Request) -> Response:
        form = await req.form()
        return _json_response(adapter.handle_webauthn_register_start(_form_request(req, {k: v for k, v in form.items() if isinstance(v, str)})))

    @app.post("/webauthn/register/finish")
    async def webauthn_register_finish(req: Request) -> Response:
        form = await req.form()
        return _json_response(adapter.handle_webauthn_register_finish(_form_request(req, {k: v for k, v in form.items() if isinstance(v, str)})))

    @app.post("/webauthn/authenticate/start")
    async def webauthn_authenticate_start(req: Request) -> Response:
        form = await req.form()
        return _json_response(adapter.handle_webauthn_authenticate_start(_form_request(req, {k: v for k, v in form.items() if isinstance(v, str)})))

    @app.post("/webauthn/authenticate/finish")
    async def webauthn_authenticate_finish(req: Request) -> Response:
        form = await req.form()
        return _json_response(adapter.handle_webauthn_authenticate_finish(_form_request(req, {k: v for k, v in form.items() if isinstance(v, str)})))

    @app.post("/oidc/login/start")
    async def oidc_login_start(req: Request) -> Response:
        form = await req.form()
        return _json_response(adapter.handle_oidc_login_start(_form_request(req, {k: v for k, v in form.items() if isinstance(v, str)})))

    @app.get("/oidc/callback")
    async def oidc_callback(req: Request) -> Response:
        return _json_response(adapter.handle_oidc_callback(_form_request(req, {})))

    @app.get("/.well-known/jwks.json")
    async def jwks(req: Request) -> Response:
        return _json_response(adapter.handle_jwks(_form_request(req, {})))

    @app.get("/.well-known/openid-configuration")
    async def oidc_conf() -> Response:
        return _json_response(adapter.handle_openid_configuration(issuer="https://auth.local"))

