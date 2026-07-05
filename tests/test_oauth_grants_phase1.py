import hmac

import pytest

from astraauth.core.authorization.engine import AuthorizationEngine
from astraauth.core.authorization.models import Role, TenantRoleAssignment
from astraauth.core.authorization.scope_policy import DefaultScopePolicy
from astraauth.core.authorization.store import InMemoryAssignmentStore, InMemoryRoleStore
from astraauth.core.config.settings import AuthConfig
from astraauth.core.oauth.api_key import (
    APIKeyRecord,
    InMemoryAPIKeyAuthenticator,
    Sha256APIKeyHasher,
)
from astraauth.core.oauth.inmemory import (
    InMemoryAuthorizationCodeStore,
    InMemoryClientRegistry,
    InMemorySubjectDirectory,
)
from astraauth.core.oauth.models import OAuthClient, Subject
from astraauth.core.oauth.password import (
    InMemoryPasswordAuthenticator,
    MultiSchemePasswordVerifier,
    PasswordRecord,
    Sha256PasswordVerifier,
    hash_password,
    hash_password_legacy_sha256,
)
from astraauth.core.oauth.services import exchange_token
from astraauth.core.sessions.store import InMemorySessionStore
from astraauth.core.token.token_manager import TokenKeyManager


def _setup_common() -> tuple[
    InMemoryClientRegistry,
    InMemorySubjectDirectory,
    InMemoryAuthorizationCodeStore,
    InMemorySessionStore,
    TokenKeyManager,
    AuthorizationEngine,
    DefaultScopePolicy,
]:
    clients = InMemoryClientRegistry()
    subjects = InMemorySubjectDirectory()
    codes = InMemoryAuthorizationCodeStore()
    sessions = InMemorySessionStore()
    token_manager = TokenKeyManager(AuthConfig())

    roles = InMemoryRoleStore()
    assignments = InMemoryAssignmentStore()
    roles.add_role(Role(name="reader", permissions={"perm:openid"}))
    assignments.assign(TenantRoleAssignment(subject_id="u1", tenant_id="t1", roles={"reader"}))

    authz = AuthorizationEngine(role_store=roles, assignment_store=assignments)
    scope_policy = DefaultScopePolicy({"perm:openid": "openid"}, strict_mode=True)

    clients.add(
        OAuthClient(
            client_id="c1",
            redirect_uris={"https://client.example/cb"},
            allowed_scopes={"openid"},
            allowed_tenants={"t1"},
            client_type="public",
            auth_method="none",
        )
    )
    subjects.add(Subject(subject_id="u1", tenants={"t1"}, username="alice"))

    return clients, subjects, codes, sessions, token_manager, authz, scope_policy


def test_password_grant_issues_tokens_with_tid_claim() -> None:
    clients, subjects, codes, sessions, token_manager, authz, scope_policy = _setup_common()

    password_auth = InMemoryPasswordAuthenticator(MultiSchemePasswordVerifier())
    password_auth.add(
        tenant_id="t1",
        record=PasswordRecord(
            username="alice",
            password_hash=hash_password("secret"),
            subject=Subject(subject_id="u1", tenants={"t1"}, username="alice"),
        ),
    )

    resp = exchange_token(
        grant_type="password",
        client_id="c1",
        tenant_id="t1",
        redirect_uri=None,
        code=None,
        code_verifier=None,
        refresh_token=None,
        requested_scopes={"openid"},
        username="alice",
        password="secret",
        api_key=None,
        clients=clients,
        subjects=subjects,
        codes=codes,
        session_store=sessions,
        token_manager=token_manager,
        access_token_audience="api",
        session_ttl_seconds=300,
        scope_policy=scope_policy,
        authorization_engine=authz,
        authorization_header=None,
        form_client_secret=None,
        client_assertion=None,
        client_assertion_type=None,
        token_endpoint="https://auth.server/token",
        password_authenticator=password_auth,
        api_key_authenticator=None,
    )

    claims = token_manager.verify_jwt(resp.access_token, audience="api")
    assert claims["tid"] == "t1"
    assert claims["sub"] == "u1"
    assert resp.refresh_token is not None


def test_api_key_grant_issues_tokens_with_tid_claim() -> None:
    clients, subjects, codes, sessions, token_manager, authz, scope_policy = _setup_common()

    api_key_auth = InMemoryAPIKeyAuthenticator(Sha256APIKeyHasher())
    api_key_auth.add(
        tenant_id="t1",
        label="default",
        record=APIKeyRecord(
            key_digest=Sha256APIKeyHasher().digest(api_key="k-123"),
            subject=Subject(subject_id="u1", tenants={"t1"}, username="alice"),
        ),
    )

    resp = exchange_token(
        grant_type="urn:astraauth:grant-type:api_key",
        client_id="c1",
        tenant_id="t1",
        redirect_uri=None,
        code=None,
        code_verifier=None,
        refresh_token=None,
        requested_scopes={"openid"},
        username=None,
        password=None,
        api_key="k-123",
        clients=clients,
        subjects=subjects,
        codes=codes,
        session_store=sessions,
        token_manager=token_manager,
        access_token_audience="api",
        session_ttl_seconds=300,
        scope_policy=scope_policy,
        authorization_engine=authz,
        authorization_header=None,
        form_client_secret=None,
        client_assertion=None,
        client_assertion_type=None,
        token_endpoint="https://auth.server/token",
        password_authenticator=None,
        api_key_authenticator=api_key_auth,
    )

    claims = token_manager.verify_jwt(resp.access_token, audience="api")
    assert claims["tid"] == "t1"
    assert claims["sub"] == "u1"
    assert resp.refresh_token is not None


def test_api_key_authenticator_scans_all_candidate_records(monkeypatch: pytest.MonkeyPatch) -> None:
    authenticator = InMemoryAPIKeyAuthenticator(Sha256APIKeyHasher())
    digest = Sha256APIKeyHasher().digest(api_key="k-123")
    expected_subject = Subject(subject_id="u1", tenants={"t1"}, username="alice")
    authenticator.add(
        tenant_id="t1",
        label="first-match",
        record=APIKeyRecord(key_digest=digest, subject=expected_subject),
    )
    authenticator.add(
        tenant_id="t1",
        label="second-miss",
        record=APIKeyRecord(
            key_digest=Sha256APIKeyHasher().digest(api_key="other-key"),
            subject=Subject(subject_id="u2", tenants={"t1"}, username="bob"),
        ),
    )
    authenticator.add(
        tenant_id="t1",
        label="revoked",
        record=APIKeyRecord(
            key_digest=digest,
            subject=Subject(subject_id="u3", tenants={"t1"}, username="carol"),
            revoked=True,
        ),
    )

    calls: list[tuple[str, str]] = []
    original_compare_digest = hmac.compare_digest

    def recording_compare_digest(left: str, right: str) -> bool:
        calls.append((left, right))
        return original_compare_digest(left, right)

    monkeypatch.setattr(
        "astraauth.core.oauth.api_key.hmac.compare_digest",
        recording_compare_digest,
    )

    subject = authenticator.authenticate(api_key="k-123", tenant_id="t1")

    assert subject == expected_subject
    assert len(calls) == 2
    assert calls[0][0] == digest
    assert calls[1][0] != digest


def test_multi_scheme_password_verifier_accepts_legacy_sha256_and_upgrades_record() -> None:
    verifier = MultiSchemePasswordVerifier()
    authenticator = InMemoryPasswordAuthenticator(verifier)
    record = PasswordRecord(
        username="alice",
        password_hash=hash_password_legacy_sha256("secret"),
        subject=Subject(subject_id="u1", tenants={"t1"}, username="alice"),
    )
    authenticator.add(tenant_id="t1", record=record)

    subject = authenticator.authenticate(username="alice", password="secret", tenant_id="t1")

    assert subject is not None
    assert authenticator.needs_rehash(username="alice", tenant_id="t1") is False


def test_sha256_password_verifier_still_validates_legacy_hashes() -> None:
    verifier = Sha256PasswordVerifier()
    legacy_hash = hash_password_legacy_sha256("secret")

    assert verifier.verify(provided_password="secret", stored_password_hash=legacy_hash) is True
    assert verifier.verify(provided_password="wrong", stored_password_hash=legacy_hash) is False
