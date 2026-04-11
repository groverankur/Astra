# mypy: disable-error-code="untyped-decorator"

from astraauth_core.adapters.http_types import HttpResponse, NormalizedRequestContext
from astraauth_core.adapters.oauth_http import OAuthHTTPAdapter
from robyn import Request, Response, Robyn


def _request(request: Request, form_data: dict[str, str]) -> NormalizedRequestContext:
    return NormalizedRequestContext(
        http_method=request.method,
        request_path=request.url.path,
        query_params=getattr(request, "query_params", {}),
        headers=request.headers,
        form_data=form_data,
        cookies=getattr(request, "cookies", {}),
        client_ip=getattr(request, "ip_addr", None),
        body_json=None,
    )


def _response(resp: HttpResponse) -> Response:
    return Response(json=resp.body, status_code=resp.status, headers=resp.headers or {})


def mount_oauth(app: Robyn, adapter: OAuthHTTPAdapter) -> None:  # noqa: C901
    @app.get("/authorize")
    async def authorize(request: Request) -> Response:
        resp = adapter.handle_authorize(_request(request, {}))
        if resp.status == 302:
            return Response(status_code=302, headers=resp.headers or {})
        return _response(resp)

    @app.post("/token")
    async def token(request: Request) -> Response:
        form = await request.form()
        return _response(adapter.handle_token(_request(request, {k: v for k, v in form.items() if isinstance(v, str)})))

    @app.post("/logout")
    async def logout(request: Request) -> Response:
        form = await request.form()
        return _response(adapter.handle_logout(_request(request, {k: v for k, v in form.items() if isinstance(v, str)})))

    @app.post("/introspect")
    async def introspect(request: Request) -> Response:
        form = await request.form()
        return _response(adapter.handle_introspect(_request(request, {k: v for k, v in form.items() if isinstance(v, str)})))

    @app.post("/mfa/challenge")
    async def mfa_challenge(request: Request) -> Response:
        form = await request.form()
        return _response(adapter.handle_mfa_challenge(_request(request, {k: v for k, v in form.items() if isinstance(v, str)})))

    @app.post("/mfa/verify")
    async def mfa_verify(request: Request) -> Response:
        form = await request.form()
        return _response(adapter.handle_mfa_verify(_request(request, {k: v for k, v in form.items() if isinstance(v, str)})))

    @app.post("/webauthn/register/start")
    async def webauthn_register_start(request: Request) -> Response:
        form = await request.form()
        return _response(adapter.handle_webauthn_register_start(_request(request, {k: v for k, v in form.items() if isinstance(v, str)})))

    @app.post("/webauthn/register/finish")
    async def webauthn_register_finish(request: Request) -> Response:
        form = await request.form()
        return _response(adapter.handle_webauthn_register_finish(_request(request, {k: v for k, v in form.items() if isinstance(v, str)})))

    @app.post("/webauthn/authenticate/start")
    async def webauthn_authenticate_start(request: Request) -> Response:
        form = await request.form()
        return _response(adapter.handle_webauthn_authenticate_start(_request(request, {k: v for k, v in form.items() if isinstance(v, str)})))

    @app.post("/webauthn/authenticate/finish")
    async def webauthn_authenticate_finish(request: Request) -> Response:
        form = await request.form()
        return _response(adapter.handle_webauthn_authenticate_finish(_request(request, {k: v for k, v in form.items() if isinstance(v, str)})))

    @app.post("/oidc/login/start")
    async def oidc_login_start(request: Request) -> Response:
        form = await request.form()
        resp = adapter.handle_oidc_login_start(_request(request, {k: v for k, v in form.items() if isinstance(v, str)}))
        if resp.status == 302:
            return Response(status_code=302, headers=resp.headers or {})
        return _response(resp)

    @app.get("/oidc/callback")
    async def oidc_callback(request: Request) -> Response:
        return _response(adapter.handle_oidc_callback(_request(request, {})))

    @app.get("/.well-known/jwks.json")
    async def jwks(request: Request) -> Response:
        return _response(adapter.handle_jwks(_request(request, {})))

    @app.get("/.well-known/openid-configuration")
    async def oidc_conf(request: Request) -> Response:
        _ = request
        return _response(adapter.handle_openid_configuration(issuer="https://auth.local"))

