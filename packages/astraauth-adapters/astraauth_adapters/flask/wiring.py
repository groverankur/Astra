# mypy: disable-error-code="untyped-decorator"

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from astraauth_core.adapters.http_types import HttpResponse, NormalizedRequestContext
from astraauth_core.adapters.oauth_http import OAuthHTTPAdapter

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


def _to_flask_response(response: HttpResponse) -> Any:
    from flask import jsonify, redirect

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


def mount_oauth(app: Flask, adapter: OAuthHTTPAdapter, *, issuer: str = "https://auth.local") -> None:  # noqa: C901
    from flask import request

    @app.get("/authorize")
    def authorize() -> Any:
        return _to_flask_response(adapter.handle_authorize(_request_context(request)))

    @app.post("/token")
    def token() -> Any:
        return _to_flask_response(adapter.handle_token(_request_context(request)))

    @app.post("/logout")
    def logout() -> Any:
        return _to_flask_response(adapter.handle_logout(_request_context(request)))

    @app.post("/introspect")
    def introspect() -> Any:
        return _to_flask_response(adapter.handle_introspect(_request_context(request)))

    @app.post("/mfa/challenge")
    def mfa_challenge() -> Any:
        return _to_flask_response(adapter.handle_mfa_challenge(_request_context(request)))

    @app.post("/mfa/verify")
    def mfa_verify() -> Any:
        return _to_flask_response(adapter.handle_mfa_verify(_request_context(request)))

    @app.post("/webauthn/register/start")
    def webauthn_register_start() -> Any:
        return _to_flask_response(adapter.handle_webauthn_register_start(_request_context(request)))

    @app.post("/webauthn/register/finish")
    def webauthn_register_finish() -> Any:
        return _to_flask_response(adapter.handle_webauthn_register_finish(_request_context(request)))

    @app.post("/webauthn/authenticate/start")
    def webauthn_authenticate_start() -> Any:
        return _to_flask_response(adapter.handle_webauthn_authenticate_start(_request_context(request)))

    @app.post("/webauthn/authenticate/finish")
    def webauthn_authenticate_finish() -> Any:
        return _to_flask_response(adapter.handle_webauthn_authenticate_finish(_request_context(request)))

    @app.post("/oidc/login/start")
    def oidc_login_start() -> Any:
        return _to_flask_response(adapter.handle_oidc_login_start(_request_context(request)))

    @app.get("/oidc/callback")
    def oidc_callback() -> Any:
        return _to_flask_response(adapter.handle_oidc_callback(_request_context(request)))

    @app.get("/.well-known/jwks.json")
    def jwks() -> Any:
        return _to_flask_response(adapter.handle_jwks(_request_context(request)))

    @app.get("/.well-known/openid-configuration")
    def openid_configuration() -> Any:
        return _to_flask_response(adapter.handle_openid_configuration(issuer=issuer))
