from typing import Any, cast

from robyn import Request, Response, Robyn

from astraauth.adapters.origin import (
    AdapterOriginPolicy,
    call_with_origin_policy,
    preflight_response,
)
from astraauth.core.adapters.http_types import HttpResponse, NormalizedRequestContext
from astraauth.core.adapters.oauth_http import OAuthHTTPAdapter
from astraauth.core.adapters.security_headers import apply_runtime_security_headers


def _request(request: Request, form_data: dict[str, str]) -> NormalizedRequestContext:
    return NormalizedRequestContext(
        http_method=request.method,
        request_path=request.url.path,
        query_params={
            str(key): str(value)
            for key, value in cast(dict[str, str], getattr(request, "query_params", {})).items()
        },
        headers={
            str(key): str(value) for key, value in cast(dict[str, str], request.headers).items()
        },
        form_data=form_data,
        cookies=getattr(request, "cookies", {}),
        client_ip=getattr(request, "ip_addr", None),
        body_json=None,
    )


def _response(resp: HttpResponse, *, allow_caching: bool = False) -> Response:
    import json

    resp = apply_runtime_security_headers(resp, allow_caching=allow_caching)
    return Response(resp.status, resp.headers or {}, json.dumps(resp.body))


async def _extract_form_data(request: Request) -> dict[str, str]:
    form_method = cast(Any, getattr(request, "form", None))
    if not callable(form_method):
        return {}
    form = await form_method()
    if not hasattr(form, "items"):
        return {}
    return {str(k): str(v) for k, v in form.items() if isinstance(v, str)}


def mount_oauth(  # noqa: C901
    app: Robyn,
    adapter: OAuthHTTPAdapter,
    *,
    origin_policy: AdapterOriginPolicy | None = None,
) -> None:
    async def _call(
        request: Request,
        handler: Any,
        *,
        form_data: dict[str, str] | None = None,
        allow_caching: bool = False,
    ) -> Response:
        req = _request(
            request, form_data if form_data is not None else await _extract_form_data(request)
        )
        resp = call_with_origin_policy(req, handler, policy=origin_policy)
        return _response(resp, allow_caching=allow_caching)

    @app.options("/{path:path}")
    async def cors_preflight(request: Request) -> Response:
        return _response(preflight_response(_request(request, {}), policy=origin_policy))

    @app.get("/authorize")
    async def authorize(request: Request) -> Response:
        resp = call_with_origin_policy(
            _request(request, {}), adapter.handle_authorize, policy=origin_policy
        )
        if resp.status == 302:
            return Response(302, resp.headers or {}, "")
        return _response(resp)

    @app.post("/token")
    async def token(request: Request) -> Response:
        return await _call(request, adapter.handle_token)

    @app.post("/logout")
    async def logout(request: Request) -> Response:
        return await _call(request, adapter.handle_logout)

    @app.post("/introspect")
    async def introspect(request: Request) -> Response:
        return await _call(request, adapter.handle_introspect)

    @app.post("/mfa/challenge")
    async def mfa_challenge(request: Request) -> Response:
        return await _call(request, adapter.handle_mfa_challenge)

    @app.post("/mfa/verify")
    async def mfa_verify(request: Request) -> Response:
        return await _call(request, adapter.handle_mfa_verify)

    @app.post("/webauthn/register/start")
    async def webauthn_register_start(request: Request) -> Response:
        return await _call(request, adapter.handle_webauthn_register_start)

    @app.post("/webauthn/register/finish")
    async def webauthn_register_finish(request: Request) -> Response:
        return await _call(request, adapter.handle_webauthn_register_finish)

    @app.post("/webauthn/authenticate/start")
    async def webauthn_authenticate_start(request: Request) -> Response:
        return await _call(request, adapter.handle_webauthn_authenticate_start)

    @app.post("/webauthn/authenticate/finish")
    async def webauthn_authenticate_finish(request: Request) -> Response:
        return await _call(request, adapter.handle_webauthn_authenticate_finish)

    @app.post("/oidc/login/start")
    async def oidc_login_start(request: Request) -> Response:
        req = _request(request, await _extract_form_data(request))
        resp = call_with_origin_policy(req, adapter.handle_oidc_login_start, policy=origin_policy)
        if resp.status == 302:
            return Response(302, resp.headers or {}, "")
        return _response(resp)

    @app.get("/oidc/callback")
    async def oidc_callback(request: Request) -> Response:
        return await _call(request, adapter.handle_oidc_callback, form_data={})

    @app.get("/.well-known/jwks.json")
    async def jwks(request: Request) -> Response:
        return await _call(request, adapter.handle_jwks, form_data={}, allow_caching=True)

    @app.get("/.well-known/openid-configuration")
    async def oidc_conf(request: Request) -> Response:
        _ = request
        return _response(
            adapter.handle_openid_configuration(issuer="https://auth.local"),
            allow_caching=True,
        )
