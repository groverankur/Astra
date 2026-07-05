from __future__ import annotations

from typing import TYPE_CHECKING, Any

from astraauth.adapters.origin import (
    AdapterOriginPolicy,
    call_with_origin_policy,
    preflight_response,
)
from astraauth.core.adapters.http_types import HttpResponse, NormalizedRequestContext
from astraauth.core.adapters.oauth_http import OAuthHTTPAdapter
from astraauth.core.adapters.security_headers import apply_runtime_security_headers

if TYPE_CHECKING:
    from flask import Flask


def _request_context(request: Any) -> NormalizedRequestContext:
    return NormalizedRequestContext(
        http_method=request.method,
        request_path=str(request.path),
        query_params=dict(request.args.items()),
        headers=dict(request.headers.items()),
        form_data=dict(request.form.items()),
        cookies=request.cookies,
        client_ip=request.remote_addr,
        body_json=request.get_json(silent=True),
    )


def _to_flask_response(response: HttpResponse, *, allow_caching: bool = False) -> Any:
    from flask import jsonify, redirect

    response = apply_runtime_security_headers(response, allow_caching=allow_caching)
    if response.status == 302 and response.headers and "Location" in response.headers:
        headers = dict(response.headers)
        flask_response = redirect(headers.pop("Location"), code=302)
        for key, value in headers.items():
            flask_response.headers[key] = value
        return flask_response
    payload = response.body if isinstance(response.body, dict) else {"body": response.body}
    flask_response = jsonify(payload)
    flask_response.status_code = response.status
    for key, value in (response.headers or {}).items():
        flask_response.headers[key] = value
    return flask_response


def mount_oauth(  # noqa: C901
    app: Flask,
    adapter: OAuthHTTPAdapter,
    *,
    issuer: str = "https://auth.local",
    origin_policy: AdapterOriginPolicy | None = None,
) -> None:
    from flask import request

    def _call(handler: Any, *, allow_caching: bool = False) -> Any:
        req = _request_context(request)
        return _to_flask_response(
            call_with_origin_policy(req, handler, policy=origin_policy),
            allow_caching=allow_caching,
        )

    @app.before_request
    def cors_preflight() -> Any:
        if request.method != "OPTIONS":
            return None
        return _to_flask_response(
            preflight_response(_request_context(request), policy=origin_policy)
        )

    @app.get("/authorize")
    def authorize() -> Any:
        return _call(adapter.handle_authorize)

    @app.post("/token")
    def token() -> Any:
        return _call(adapter.handle_token)

    @app.post("/logout")
    def logout() -> Any:
        return _call(adapter.handle_logout)

    @app.post("/introspect")
    def introspect() -> Any:
        return _call(adapter.handle_introspect)

    @app.post("/mfa/challenge")
    def mfa_challenge() -> Any:
        return _call(adapter.handle_mfa_challenge)

    @app.post("/mfa/verify")
    def mfa_verify() -> Any:
        return _call(adapter.handle_mfa_verify)

    @app.post("/webauthn/register/start")
    def webauthn_register_start() -> Any:
        return _call(adapter.handle_webauthn_register_start)

    @app.post("/webauthn/register/finish")
    def webauthn_register_finish() -> Any:
        return _call(adapter.handle_webauthn_register_finish)

    @app.post("/webauthn/authenticate/start")
    def webauthn_authenticate_start() -> Any:
        return _call(adapter.handle_webauthn_authenticate_start)

    @app.post("/webauthn/authenticate/finish")
    def webauthn_authenticate_finish() -> Any:
        return _call(adapter.handle_webauthn_authenticate_finish)

    @app.post("/oidc/login/start")
    def oidc_login_start() -> Any:
        return _call(adapter.handle_oidc_login_start)

    @app.get("/oidc/callback")
    def oidc_callback() -> Any:
        return _call(adapter.handle_oidc_callback)

    @app.get("/.well-known/jwks.json")
    def jwks() -> Any:
        return _call(adapter.handle_jwks, allow_caching=True)

    @app.get("/.well-known/openid-configuration")
    def openid_configuration() -> Any:
        return _to_flask_response(
            adapter.handle_openid_configuration(issuer=issuer),
            allow_caching=True,
        )
