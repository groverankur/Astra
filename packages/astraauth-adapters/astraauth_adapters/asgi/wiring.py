from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import parse_qsl

from astraauth_core.adapters.http_types import HttpResponse, NormalizedRequestContext
from astraauth_core.adapters.oauth_http import OAuthHTTPAdapter

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]


def _decode_body(body: bytes) -> dict[str, str]:
    return dict(parse_qsl(body.decode("utf-8"), keep_blank_values=True))


def _headers_map(scope: Scope) -> dict[str, str]:
    raw_headers = scope.get("headers", [])
    if not isinstance(raw_headers, list):
        return {}
    return {
        bytes(key).decode("latin-1"): bytes(value).decode("latin-1")
        for key, value in raw_headers
    }


def _cookies_from_headers(headers: dict[str, str]) -> dict[str, str]:
    raw_cookie = headers.get("cookie")
    if not raw_cookie:
        return {}
    cookies: dict[str, str] = {}
    for chunk in raw_cookie.split(";"):
        if "=" not in chunk:
            continue
        key, value = chunk.split("=", 1)
        cookies[key.strip()] = value.strip()
    return cookies


def _to_request_context(scope: Scope, body: bytes) -> NormalizedRequestContext:
    headers = _headers_map(scope)
    query_string = scope.get("query_string", b"")
    query_params = dict(parse_qsl(bytes(query_string).decode("utf-8"), keep_blank_values=True))
    form_data = _decode_body(body) if body else {}
    client = scope.get("client")
    client_ip = client[0] if isinstance(client, tuple) and client else None
    return NormalizedRequestContext(
        http_method=str(scope.get("method", "GET")),
        request_path=str(scope.get("path", "/")),
        query_params=query_params,
        headers=headers,
        form_data=form_data,
        cookies=_cookies_from_headers(headers),
        client_ip=client_ip,
    )


def _response_bytes(body: dict[str, object] | str | None) -> bytes:
    if body is None:
        return b""
    if isinstance(body, dict):
        return json.dumps(body).encode("utf-8")
    return body.encode("utf-8")


class ASGIOAuthApp:
    def __init__(self, *, adapter: OAuthHTTPAdapter, issuer: str = "https://auth.local") -> None:
        self._adapter = adapter
        self._issuer = issuer

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await send({"type": "http.response.start", "status": 404, "headers": []})
            await send({"type": "http.response.body", "body": b""})
            return

        body = b""
        more_body = True
        while more_body:
            message = await receive()
            body += bytes(message.get("body", b""))
            more_body = bool(message.get("more_body", False))

        response = self._dispatch(scope, body)
        response_headers = [
            (key.encode("latin-1"), value.encode("latin-1"))
            for key, value in (response.headers or {}).items()
        ]
        if response.body is not None and "content-type" not in {key.lower() for key, _ in (response.headers or {}).items()}:
            response_headers.append((b"content-type", b"application/json"))

        await send(
            {
                "type": "http.response.start",
                "status": response.status,
                "headers": response_headers,
            }
        )
        await send({"type": "http.response.body", "body": _response_bytes(response.body)})

    def _dispatch(self, scope: Scope, body: bytes) -> HttpResponse:
        request = _to_request_context(scope, body)
        method = request.http_method.upper()
        path = request.request_path
        routes: dict[tuple[str, str], Callable[[NormalizedRequestContext], HttpResponse]] = {
            ("GET", "/authorize"): self._adapter.handle_authorize,
            ("POST", "/token"): self._adapter.handle_token,
            ("POST", "/logout"): self._adapter.handle_logout,
            ("POST", "/introspect"): self._adapter.handle_introspect,
            ("POST", "/mfa/challenge"): self._adapter.handle_mfa_challenge,
            ("POST", "/mfa/verify"): self._adapter.handle_mfa_verify,
            ("POST", "/webauthn/register/start"): self._adapter.handle_webauthn_register_start,
            ("POST", "/webauthn/register/finish"): self._adapter.handle_webauthn_register_finish,
            ("POST", "/webauthn/authenticate/start"): self._adapter.handle_webauthn_authenticate_start,
            ("POST", "/webauthn/authenticate/finish"): self._adapter.handle_webauthn_authenticate_finish,
            ("POST", "/oidc/login/start"): self._adapter.handle_oidc_login_start,
            ("GET", "/oidc/callback"): self._adapter.handle_oidc_callback,
            ("GET", "/.well-known/jwks.json"): self._adapter.handle_jwks,
        }
        if (method, path) == ("GET", "/.well-known/openid-configuration"):
            return self._adapter.handle_openid_configuration(issuer=self._issuer)
        handler = routes.get((method, path))
        if handler is None:
            return HttpResponse(status=404, body={"error": "not_found"})
        return handler(request)


def create_asgi_app(*, adapter: OAuthHTTPAdapter, issuer: str = "https://auth.local") -> ASGIOAuthApp:
    return ASGIOAuthApp(adapter=adapter, issuer=issuer)
