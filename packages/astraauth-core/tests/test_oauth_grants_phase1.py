from astraauth_core.authorization.engine import AuthorizationEngine
from astraauth_core.authorization.models import Role, TenantRoleAssignment
from astraauth_core.authorization.scope_policy import DefaultScopePolicy
from astraauth_core.authorization.store import InMemoryAssignmentStore, InMemoryRoleStore
from astraauth_core.config.settings import AuthConfig
from astraauth_core.oauth.api_key import (
    APIKeyRecord,
    InMemoryAPIKeyAuthenticator,
    Sha256APIKeyHasher,
)
from astraauth_core.oauth.inmemory import (
    InMemoryAuthorizationCodeStore,
    InMemoryClientRegistry,
    InMemorySubjectDirectory,
)
from astraauth_core.oauth.models import OAuthClient, Subject
from astraauth_core.oauth.password import (
    InMemoryPasswordAuthenticator,
    PasswordRecord,
    Sha256PasswordVerifier,
    hash_password,
)
from astraauth_core.oauth.services import exchange_token
from astraauth_core.sessions.store import InMemorySessionStore
from astraauth_core.token.token_manager import TokenKeyManager


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

    password_auth = InMemoryPasswordAuthenticator(Sha256PasswordVerifier())
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
