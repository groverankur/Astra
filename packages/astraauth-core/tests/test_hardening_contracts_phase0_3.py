from astraauth_core.adapters.http_types import NormalizedRequestContext
from astraauth_core.adapters.oauth_http import OAuthHTTPAdapter
from astraauth_core.authorization.engine import AuthorizationEngine
from astraauth_core.authorization.scope_policy import DefaultScopePolicy
from astraauth_core.authorization.store import InMemoryAssignmentStore, InMemoryRoleStore
from astraauth_core.config.settings import AuthConfig
from astraauth_core.oauth.inmemory import (
    InMemoryAuthorizationCodeStore,
    InMemoryClientRegistry,
    InMemorySubjectDirectory,
)
from astraauth_core.sessions.introspection import introspect_access_token
from astraauth_core.sessions.models import Session
from astraauth_core.sessions.store import InMemorySessionStore
from astraauth_core.token.token_manager import TokenKeyManager


def _build_adapter() -> OAuthHTTPAdapter:
    authz = AuthorizationEngine(
        role_store=InMemoryRoleStore(),
        assignment_store=InMemoryAssignmentStore(),
    )
    return OAuthHTTPAdapter(
        clients=InMemoryClientRegistry(),
        subjects=InMemorySubjectDirectory(),
        codes=InMemoryAuthorizationCodeStore(),
        session_store=InMemorySessionStore(),
        token_manager=TokenKeyManager(AuthConfig()),
        access_token_audience="api",
        code_ttl_seconds=300,
        session_ttl_seconds=3600,
        authorization_engine=authz,
        scope_policy=DefaultScopePolicy(permission_scope_map={}, strict_mode=True),
    )


def test_normalized_request_context_accessors() -> None:
    req = NormalizedRequestContext(
        http_method="POST",
        request_path="/token",
        query_params={"a": "1"},
        headers={"Authorization": "Bearer t"},
        form_data={"grant_type": "refresh_token"},
        cookies={"sid": "s1"},
        client_ip="127.0.0.1",
    )
    assert req.method() == "POST"
    assert req.path() == "/token"
    assert req.query("a") == "1"
    assert req.header("Authorization") == "Bearer t"
    assert req.form("grant_type") == "refresh_token"
    assert req.cookie("sid") == "s1"
    assert req.ip() == "127.0.0.1"


def test_invalid_client_error_maps_to_401() -> None:
    adapter = _build_adapter()
    req = NormalizedRequestContext(
        http_method="POST",
        request_path="/token",
        query_params={},
        headers={},
        form_data={
            "grant_type": "authorization_code",
            "client_id": "missing-client",
            "code": "abc",
            "redirect_uri": "https://client.example/cb",
            "code_verifier": "verifier",
        },
    )
    resp = adapter.handle_token(req)
    assert resp.status == 401
    assert isinstance(resp.body, dict)
    assert resp.body["error"] == "invalid_client"


def test_access_token_introspection_enforces_tid_sid_ver_invariants() -> None:
    store = InMemorySessionStore()
    token_manager = TokenKeyManager(AuthConfig())
    session = Session.create(
        subject_id="u1",
        tenant_id="t1",
        client_id="c1",
        requested_scopes={"openid"},
        ttl_seconds=300,
    )
    store.save(session)

    valid = token_manager.issue_jwt(
        subject="u1",
        audience="api",
        extra_claims={"sid": session.session_id, "tid": "t1", "ver": session.version},
    )
    missing_tid = token_manager.issue_jwt(
        subject="u1",
        audience="api",
        extra_claims={"sid": session.session_id, "ver": session.version},
    )
    wrong_ver = token_manager.issue_jwt(
        subject="u1",
        audience="api",
        extra_claims={"sid": session.session_id, "tid": "t1", "ver": session.version + 1},
    )

    assert (
        introspect_access_token(
            valid,
            token_manager=token_manager,
            expected_audience="api",
            session_store=store,
        )["active"]
        is True
    )
    assert (
        introspect_access_token(
            missing_tid,
            token_manager=token_manager,
            expected_audience="api",
            session_store=store,
        )["active"]
        is False
    )
    assert (
        introspect_access_token(
            wrong_ver,
            token_manager=token_manager,
            expected_audience="api",
            session_store=store,
        )["active"]
        is False
    )
