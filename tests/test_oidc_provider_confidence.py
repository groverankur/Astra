from __future__ import annotations

import json
import threading
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from joserfc import jwk, jws

from astraauth.core.adapters.http_types import NormalizedRequestContext
from astraauth.core.authorization.models import Role
from astraauth.core.oauth.models import OAuthClient
from astraauth.idp import ClaimAttributeMapping, GroupRoleMapping, OIDCProviderConfig
from astraauth.service import build_inmemory_service


@dataclass(frozen=True)
class _TokenScenario:
    code: str
    access_token: str
    redirect_uri: str
    code_verifier: str
    subject: str
    email: str
    groups: tuple[str, ...]
    department: str
    expected_nonce: str
    issuer_override: str | None = None
    audience_override: tuple[str, ...] | None = None
    nonce_override: str | None = None


class _OIDCTestProvider:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._key = jwk.RSAKey.generate_key(2048)
        self._codes: dict[str, _TokenScenario] = {}
        self._access_tokens: dict[str, _TokenScenario] = {}
        self.base_url = ""
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler_class())
        self._server.timeout = 0.5
        address = self._server.server_address
        host = address[0].decode("utf-8") if isinstance(address[0], bytes) else str(address[0])
        port = int(address[1])
        self.base_url = f"http://{host}:{port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)

    def register_code(
        self,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str,
        expected_nonce: str,
        subject: str = "ext-user-1",
        email: str = "alice@example.com",
        groups: tuple[str, ...] = ("admins",),
        department: str = "Finance",
        issuer_override: str | None = None,
        audience_override: tuple[str, ...] | None = None,
        nonce_override: str | None = None,
    ) -> None:
        scenario = _TokenScenario(
            code=code,
            access_token=f"access-{code}",
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
            subject=subject,
            email=email,
            groups=groups,
            department=department,
            expected_nonce=expected_nonce,
            issuer_override=issuer_override,
            audience_override=audience_override,
            nonce_override=nonce_override,
        )
        with self._lock:
            self._codes[code] = scenario

    def rotate_signing_key(self) -> None:
        with self._lock:
            self._key = jwk.RSAKey.generate_key(2048)

    def discovery_document(self) -> dict[str, object]:
        return {
            "issuer": self.base_url,
            "authorization_endpoint": f"{self.base_url}/oauth2/authorize",
            "token_endpoint": f"{self.base_url}/oauth2/token",
            "jwks_uri": f"{self.base_url}/oauth2/jwks",
            "userinfo_endpoint": f"{self.base_url}/oauth2/userinfo",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }

    def jwks_document(self) -> dict[str, object]:
        with self._lock:
            return {"keys": [self._key.as_dict(is_private=False)]}

    def exchange_code(self, form: dict[str, str]) -> tuple[int, dict[str, object]]:
        code = form.get("code")
        redirect_uri = form.get("redirect_uri")
        code_verifier = form.get("code_verifier")
        if code is None:
            return 400, {"error": "missing_code"}
        with self._lock:
            scenario = self._codes.get(code)
            key = self._key
        if scenario is None:
            return 400, {"error": "invalid_code"}
        if redirect_uri != scenario.redirect_uri:
            return 400, {"error": "redirect_uri_mismatch"}
        if code_verifier != scenario.code_verifier:
            return 400, {"error": "invalid_code_verifier"}
        now = datetime.now(tz=UTC)
        payload = {
            "iss": scenario.issuer_override or self.base_url,
            "sub": scenario.subject,
            "aud": list(scenario.audience_override or ("ext-client",)),
            "nonce": scenario.nonce_override or scenario.expected_nonce,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
        }
        id_token = jws.serialize_compact(
            protected={"alg": "RS256"},
            payload=json.dumps(payload),
            private_key=key,
        )
        with self._lock:
            self._access_tokens[scenario.access_token] = scenario
        return 200, {
            "access_token": scenario.access_token,
            "token_type": "Bearer",
            "id_token": id_token,
        }

    def userinfo(self, access_token: str | None) -> tuple[int, dict[str, object]]:
        if access_token is None:
            return 401, {"error": "missing_access_token"}
        with self._lock:
            scenario = self._access_tokens.get(access_token)
        if scenario is None:
            return 401, {"error": "invalid_access_token"}
        return 200, {
            "sub": scenario.subject,
            "email": scenario.email,
            "email_verified": True,
            "groups": list(scenario.groups),
            "department": scenario.department,
        }

    def _handler_class(self) -> type[BaseHTTPRequestHandler]:
        provider = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                parsed = urlparse(self.path)
                if parsed.path == "/.well-known/openid-configuration":
                    self._write_json(200, provider.discovery_document())
                    return
                if parsed.path == "/oauth2/jwks":
                    self._write_json(200, provider.jwks_document())
                    return
                if parsed.path == "/oauth2/userinfo":
                    auth = self.headers.get("Authorization")
                    token = (
                        auth.removeprefix("Bearer ")
                        if isinstance(auth, str) and auth.startswith("Bearer ")
                        else None
                    )
                    status, payload = provider.userinfo(token)
                    self._write_json(status, payload)
                    return
                self._write_json(404, {"error": "not_found"})

            def do_POST(self) -> None:  # noqa: N802
                parsed = urlparse(self.path)
                if parsed.path != "/oauth2/token":
                    self._write_json(404, {"error": "not_found"})
                    return
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length).decode("utf-8")
                raw = parse_qs(body)
                form = {key: values[0] for key, values in raw.items() if values}
                status, payload = provider.exchange_code(form)
                self._write_json(status, payload)

            def log_message(self, format: str, *args: object) -> None:
                _ = (format, args)

            def _write_json(self, status: int, payload: dict[str, object]) -> None:
                encoded = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

        return Handler


def _build_service(*, issuer: str, discovery_url: str) -> Any:
    svc = build_inmemory_service(default_plugins_enabled=False)
    svc.register_oidc_provider(
        provider=OIDCProviderConfig(
            provider_id="oidc-corp",
            issuer=issuer,
            client_id="ext-client",
            client_secret="ext-secret",
            discovery_url=discovery_url,
        )
    )
    svc.add_role(Role(name="employee", permissions={"openid"}))
    svc.add_role(Role(name="local_admin", permissions={"openid"}))
    svc.add_client(
        OAuthClient(
            client_id="client-1",
            redirect_uris={"https://client.local/callback"},
            allowed_scopes={"openid"},
            allowed_tenants={"tenant-1"},
            client_type="public",
            auth_method="none",
            require_pkce=False,
        )
    )
    svc.assign_roles(
        subject_id="idp:tenant-1:oidc-corp:ext-user-1",
        tenant_id="tenant-1",
        roles={"local_admin"},
    )
    svc.add_oidc_group_role_mapping(
        GroupRoleMapping(
            provider_id="oidc-corp",
            tenant_id="tenant-1",
            external_group="admins",
            role_name="employee",
        )
    )
    svc.add_oidc_claim_attribute_mapping(
        ClaimAttributeMapping(
            provider_id="oidc-corp",
            tenant_id="tenant-1",
            claim_name="department",
            attribute_name="department",
            transform="lower",
        )
    )
    return svc


def _start_login(svc: Any) -> tuple[str, Any]:
    start = svc.adapter.handle_oidc_login_start(
        NormalizedRequestContext(
            http_method="POST",
            request_path="/oidc/login/start",
            query_params={},
            headers={},
            form_data={
                "provider_id": "oidc-corp",
                "tenant_id": "tenant-1",
                "redirect_uri": "https://client.local/callback",
            },
        )
    )
    assert start.status == 302
    location = start.headers["Location"]
    state_id = parse_qs(urlparse(location).query)["state"][0]
    state = svc.oidc_login_states.get(state_id)
    assert state is not None
    return state_id, state


def _complete_callback(svc: Any, *, code: str, state_id: str) -> Any:
    return svc.adapter.handle_oidc_callback(
        NormalizedRequestContext(
            http_method="GET",
            request_path="/oidc/callback",
            query_params={
                "provider_id": "oidc-corp",
                "tenant_id": "tenant-1",
                "client_id": "client-1",
                "redirect_uri": "https://client.local/callback",
                "code": code,
                "state": state_id,
                "scope": "openid",
            },
            headers={},
        )
    )


def test_oidc_provider_fixture_end_to_end_session_issuance() -> None:
    provider = _OIDCTestProvider()
    try:
        svc = _build_service(
            issuer=provider.base_url,
            discovery_url=f"{provider.base_url}/.well-known/openid-configuration",
        )
        state_id, state = _start_login(svc)
        provider.register_code(
            code="auth-code-1",
            redirect_uri=state.redirect_uri,
            code_verifier=state.code_verifier,
            expected_nonce=state.nonce,
        )

        callback = _complete_callback(svc, code="auth-code-1", state_id=state_id)

        assert callback.status == 200
        assert callback.body["provider_id"] == "oidc-corp"
        assert callback.body["resolved_roles"] == ["employee"]
        assert callback.body["subject_attributes"] == {"department": "finance"}
        assert isinstance(callback.body["access_token"], str)
        assert isinstance(callback.body["refresh_token"], str)
        assignment = svc.assignments.get_assignments(
            "idp:tenant-1:oidc-corp:ext-user-1", "tenant-1"
        )
        assert assignment is not None
        assert assignment.roles == {"employee", "local_admin"}
        audit = svc.list_oidc_audit_records(tenant_id="tenant-1", provider_id="oidc-corp")
        assert audit[-1].status == "succeeded"
        assert audit[-1].event_type == "oidc.session.issued"
    finally:
        provider.close()


def test_oidc_provider_fixture_refreshes_jwks_after_key_rotation() -> None:
    provider = _OIDCTestProvider()
    try:
        svc = _build_service(
            issuer=provider.base_url,
            discovery_url=f"{provider.base_url}/.well-known/openid-configuration",
        )
        first_state_id, first_state = _start_login(svc)
        provider.register_code(
            code="auth-code-1",
            redirect_uri=first_state.redirect_uri,
            code_verifier=first_state.code_verifier,
            expected_nonce=first_state.nonce,
        )
        first = _complete_callback(svc, code="auth-code-1", state_id=first_state_id)
        assert first.status == 200

        provider.rotate_signing_key()

        second_state_id, second_state = _start_login(svc)
        provider.register_code(
            code="auth-code-2",
            redirect_uri=second_state.redirect_uri,
            code_verifier=second_state.code_verifier,
            expected_nonce=second_state.nonce,
        )
        second = _complete_callback(svc, code="auth-code-2", state_id=second_state_id)
        assert second.status == 200
    finally:
        provider.close()


def test_oidc_provider_fixture_rejects_bad_issuer_audience_and_nonce() -> None:
    provider = _OIDCTestProvider()
    try:
        svc = _build_service(
            issuer=provider.base_url,
            discovery_url=f"{provider.base_url}/.well-known/openid-configuration",
        )
        scenarios: list[tuple[str, str | None, tuple[str, ...] | None, str | None, str]] = [
            (
                "auth-code-issuer",
                f"{provider.base_url}/wrong",
                None,
                None,
                "id_token_issuer_mismatch",
            ),
            ("auth-code-audience", None, ("wrong-client",), None, "id_token_audience_mismatch"),
            ("auth-code-nonce", None, None, "wrong-nonce", "nonce_mismatch"),
        ]

        for code, issuer_override, audience_override, nonce_override, expected_error in scenarios:
            state_id, state = _start_login(svc)
            provider.register_code(
                code=code,
                redirect_uri=state.redirect_uri,
                code_verifier=state.code_verifier,
                expected_nonce=state.nonce,
                issuer_override=issuer_override,
                audience_override=audience_override,
                nonce_override=nonce_override,
            )
            callback = _complete_callback(svc, code=code, state_id=state_id)
            assert callback.status == 400
            assert callback.body["error"] == "oidc_callback_failed"
            assert expected_error in str(callback.body["error_description"])
            audit = svc.list_oidc_audit_records(tenant_id="tenant-1", provider_id="oidc-corp")
            assert audit[-1].status == "failed"
            assert expected_error in str(audit[-1].reason)
    finally:
        provider.close()


def test_oidc_provider_fixture_rejects_replay_callback() -> None:
    provider = _OIDCTestProvider()
    try:
        svc = _build_service(
            issuer=provider.base_url,
            discovery_url=f"{provider.base_url}/.well-known/openid-configuration",
        )
        state_id, state = _start_login(svc)
        provider.register_code(
            code="auth-code-1",
            redirect_uri=state.redirect_uri,
            code_verifier=state.code_verifier,
            expected_nonce=state.nonce,
        )

        first = _complete_callback(svc, code="auth-code-1", state_id=state_id)
        second = _complete_callback(svc, code="auth-code-1", state_id=state_id)

        assert first.status == 200
        assert second.status == 400
        assert second.body["error"] == "oidc_callback_failed"
        assert "invalid_state" in str(second.body["error_description"])
    finally:
        provider.close()


def test_oidc_provider_fixture_rejects_expired_state() -> None:
    provider = _OIDCTestProvider()
    try:
        svc = _build_service(
            issuer=provider.base_url,
            discovery_url=f"{provider.base_url}/.well-known/openid-configuration",
        )
        state_id, state = _start_login(svc)
        provider.register_code(
            code="auth-code-1",
            redirect_uri=state.redirect_uri,
            code_verifier=state.code_verifier,
            expected_nonce=state.nonce,
        )
        expired = replace(state, expires_at=datetime.now(tz=UTC) - timedelta(seconds=1))
        svc.oidc_login_states.save(expired)

        callback = _complete_callback(svc, code="auth-code-1", state_id=state_id)

        assert callback.status == 400
        assert callback.body["error"] == "oidc_callback_failed"
        assert "expired_state" in str(callback.body["error_description"])
        audit = svc.list_oidc_audit_records(tenant_id="tenant-1", provider_id="oidc-corp")
        assert audit[-1].status == "failed"
        assert audit[-1].reason == "expired_state"
    finally:
        provider.close()
