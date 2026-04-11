from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from astraauth_core.authorization.engine import AuthorizationEngine
from astraauth_core.authorization.scope_policy import ScopePolicy
from astraauth_core.oauth.client_auth import authenticate_client
from astraauth_core.oauth.errors import (
    InvalidClientError,
    InvalidGrantError,
    InvalidRequestError,
    UnsupportedGrantTypeError,
)
from astraauth_core.oauth.models import (
    AuthorizationCode,
    OAuthClient,
    PKCEParams,
    Subject,
    TokenRequestContext,
)
from astraauth_core.oauth.oidc import build_id_token_claims
from astraauth_core.oauth.pkce import verify_pkce
from astraauth_core.sessions.models import Session
from astraauth_core.sessions.services import (
    issue_session_and_refresh_token,
    rotate_refresh_token,
)
from astraauth_core.sessions.store import SessionStore
from astraauth_core.token.token_manager import TokenKeyManager

# ============================================================
# Storage Protocols
# ============================================================


class AuthorizationCodeStore(Protocol):
    def save(self, code: AuthorizationCode) -> None: ...
    def get(self, code: str) -> AuthorizationCode | None: ...
    def mark_used(self, code: str) -> None: ...


class ClientRegistry(Protocol):
    def get_client(self, client_id: str) -> OAuthClient | None: ...


class SubjectDirectory(Protocol):
    def get_subject(self, subject_id: str) -> Subject | None: ...


class PasswordAuthenticator(Protocol):
    def authenticate(self, *, username: str, password: str, tenant_id: str) -> Subject | None: ...


class APIKeyAuthenticator(Protocol):
    def authenticate(self, *, api_key: str, tenant_id: str) -> Subject | None: ...


# ============================================================
# Token Response
# ============================================================


@dataclass(frozen=True)
class TokenResponse:
    access_token: str
    id_token: str | None = None
    refresh_token: str | None = None
    token_type: str = "Bearer"
    expires_in: int | None = None


# ============================================================
# Authorization Code Flow
# ============================================================


def start_authorization(
    *,
    client_id: str,
    tenant_id: str,
    redirect_uri: str,
    scopes: set[str],
    subject_id: str,
    pkce: PKCEParams,
    nonce: str | None,
    clients: ClientRegistry,
    subjects: SubjectDirectory,
    codes: AuthorizationCodeStore,
    code_ttl_seconds: int,
) -> AuthorizationCode:
    client = clients.get_client(client_id)
    if not client:
        raise InvalidClientError("Unknown client_id")

    if client.client_type == "public":
        client.require_pkce = True

    if client.allowed_tenants is not None and tenant_id not in client.allowed_tenants:
        raise InvalidRequestError("Client not allowed for tenant")

    client.validate_redirect_uri(redirect_uri)
    client.validate_scopes(scopes)

    if client.require_pkce:
        if pkce is None:
            raise InvalidRequestError("PKCE required")
        pkce.validate()

    subject = subjects.get_subject(subject_id)
    if not subject:
        raise InvalidRequestError("Unknown subject")

    if tenant_id not in subject.tenants:
        raise InvalidRequestError("Subject not in tenant")

    code = AuthorizationCode.issue(
        client_id=client.client_id,
        tenant_id=tenant_id,
        subject_id=subject.subject_id,
        redirect_uri=redirect_uri,
        scopes=scopes,
        ttl_seconds=code_ttl_seconds,
        pkce=pkce,
        nonce=nonce,
    )

    codes.save(code)
    return code


# ============================================================
# Token Exchange
# ============================================================


def exchange_code_for_tokens(
    *,
    code: str,
    client_id: str,
    redirect_uri: str,
    code_verifier: str,
    clients: ClientRegistry,
    subjects: SubjectDirectory,
    codes: AuthorizationCodeStore,
    token_manager: TokenKeyManager,
    access_token_audience: str,
) -> TokenResponse:
    """
    Validates the authorization code + PKCE and mints tokens.
    """

    # 1) Load client
    client = clients.get_client(client_id)
    if not client:
        raise InvalidClientError("Unknown client_id")

    # 2) Load authorization code
    auth_code = codes.get(code)
    if not auth_code:
        raise InvalidGrantError("Invalid authorization code")

    # 3) Check code invariants
    if auth_code.used:
        raise InvalidGrantError("Authorization code already used")

    if auth_code.is_expired():
        raise InvalidGrantError("Authorization code expired")

    if auth_code.client_id != client.client_id:
        raise InvalidGrantError("Authorization code was not issued to this client")

    if auth_code.redirect_uri != redirect_uri:
        raise InvalidGrantError("redirect_uri mismatch")

    # 4) PKCE verification (OAuth 2.1 mandatory)
    if not verify_pkce(
        code_verifier=code_verifier,
        code_challenge=auth_code.pkce.code_challenge,
        code_challenge_method=auth_code.pkce.code_challenge_method,
    ):
        raise InvalidGrantError("PKCE verification failed")

    # 5) Load subject
    subject = subjects.get_subject(auth_code.subject_id)
    if not subject:
        raise InvalidGrantError("Unknown subject")

    # 6) Mark code as used (one-time)
    codes.mark_used(code)

    # 7) Build token context
    ctx = TokenRequestContext(
        client=client,
        subject=subject,
        scopes=auth_code.scopes,
        nonce=auth_code.nonce,
        auth_time=auth_code.issued_at,
    )

    # 8) Mint access token (JWT)
    access_token = token_manager.issue_jwt(
        subject=ctx.subject.subject_id,
        audience=access_token_audience,
        extra_claims={
            "scp": list(ctx.scopes),
            "cid": ctx.client.client_id,
        },
    )

    # 9) Mint ID token (OIDC)
    id_token_claims: dict[str, object] = {
        "aud": ctx.client.client_id,
    }
    if ctx.nonce:
        id_token_claims["nonce"] = ctx.nonce

    id_token = token_manager.issue_jwt(
        subject=ctx.subject.subject_id,
        audience=ctx.client.client_id,
        extra_claims=id_token_claims,
    )

    return TokenResponse(
        access_token=access_token,
        id_token=id_token,
        token_type="Bearer",
        expires_in=None,  # Can be filled from config later
    )


# ============================================================
# Public Dispatcher
# ============================================================


def exchange_token(
    *,
    grant_type: str,
    client_id: str,
    tenant_id: str,
    redirect_uri: str | None,
    code: str | None,
    code_verifier: str | None,
    refresh_token: str | None,
    requested_scopes: set[str] | None,
    username: str | None,
    password: str | None,
    api_key: str | None,
    clients: ClientRegistry,
    subjects: SubjectDirectory,
    codes: AuthorizationCodeStore,
    session_store: SessionStore,
    token_manager: TokenKeyManager,
    access_token_audience: str,
    session_ttl_seconds: int,
    scope_policy: ScopePolicy,
    authorization_engine: AuthorizationEngine,
    authorization_header: str | None,
    form_client_secret: str | None,
    client_assertion: str | None,
    client_assertion_type: str | None,
    token_endpoint: str,
    password_authenticator: PasswordAuthenticator | None = None,
    api_key_authenticator: APIKeyAuthenticator | None = None,
) -> TokenResponse:
    if grant_type == "authorization_code":
        return _handle_authorization_code(
            client_id=client_id,
            tenant_id=tenant_id,
            redirect_uri=redirect_uri,
            code=code,
            code_verifier=code_verifier,
            clients=clients,
            subjects=subjects,
            codes=codes,
            session_store=session_store,
            token_manager=token_manager,
            access_token_audience=access_token_audience,
            session_ttl_seconds=session_ttl_seconds,
            authorization_engine=authorization_engine,
            scope_policy=scope_policy,
            authorization_header=authorization_header,
            form_client_secret=form_client_secret,
            client_assertion=client_assertion,
            client_assertion_type=client_assertion_type,
            token_endpoint=token_endpoint,
        )

    if grant_type == "password":
        return _handle_password_token(
            client_id=client_id,
            tenant_id=tenant_id,
            username=username,
            password=password,
            requested_scopes=requested_scopes,
            clients=clients,
            session_store=session_store,
            token_manager=token_manager,
            access_token_audience=access_token_audience,
            session_ttl_seconds=session_ttl_seconds,
            authorization_engine=authorization_engine,
            scope_policy=scope_policy,
            authorization_header=authorization_header,
            form_client_secret=form_client_secret,
            client_assertion=client_assertion,
            client_assertion_type=client_assertion_type,
            token_endpoint=token_endpoint,
            password_authenticator=password_authenticator,
        )

    if grant_type == "urn:astraauth:grant-type:api_key":
        return _handle_api_key_token(
            client_id=client_id,
            tenant_id=tenant_id,
            api_key=api_key,
            requested_scopes=requested_scopes,
            clients=clients,
            session_store=session_store,
            token_manager=token_manager,
            access_token_audience=access_token_audience,
            session_ttl_seconds=session_ttl_seconds,
            authorization_engine=authorization_engine,
            scope_policy=scope_policy,
            authorization_header=authorization_header,
            form_client_secret=form_client_secret,
            client_assertion=client_assertion,
            client_assertion_type=client_assertion_type,
            token_endpoint=token_endpoint,
            api_key_authenticator=api_key_authenticator,
        )

    if grant_type == "refresh_token":
        return _handle_refresh_token(
            refresh_token=refresh_token,
            session_store=session_store,
            token_manager=token_manager,
            access_token_audience=access_token_audience,
            session_ttl_seconds=session_ttl_seconds,
            authorization_engine=authorization_engine,
            scope_policy=scope_policy,
        )

    raise UnsupportedGrantTypeError("Unsupported grant type")


# ============================================================
# Authorization Code Flow
# ============================================================


def _handle_authorization_code(
    *,
    client_id: str,
    tenant_id: str,
    redirect_uri: str | None,
    code: str | None,
    code_verifier: str | None,
    clients: ClientRegistry,
    subjects: SubjectDirectory,
    codes: AuthorizationCodeStore,
    session_store: SessionStore,
    token_manager: TokenKeyManager,
    access_token_audience: str,
    session_ttl_seconds: int,
    scope_policy: ScopePolicy,
    authorization_engine: AuthorizationEngine,
    authorization_header: str | None,
    form_client_secret: str | None,
    client_assertion: str | None,
    client_assertion_type: str | None,
    token_endpoint: str,
) -> TokenResponse:
    # ---- Explicit type narrowing ----
    if tenant_id is None:
        raise InvalidRequestError("Missing tenant_id")
    if code is None:
        raise InvalidRequestError("Missing code")

    if redirect_uri is None:
        raise InvalidRequestError("Missing redirect_uri")

    if code_verifier is None:
        raise InvalidRequestError("Missing code_verifier")

    client = clients.get_client(client_id)
    if not client:
        raise InvalidClientError("Unknown client")

    auth_code = _validate_authorization_code(
        code=code,
        redirect_uri=redirect_uri,
        client=client,
        codes=codes,
        code_verifier=code_verifier,
    )

    subject = subjects.get_subject(auth_code.subject_id)
    if not subject:
        raise InvalidGrantError("Unknown subject")

    authenticate_client(
        client=client,
        authorization_header=authorization_header,
        form_client_id=client_id,
        form_client_secret=form_client_secret,
        client_assertion=client_assertion,
        client_assertion_type=client_assertion_type,
        token_endpoint=token_endpoint,
    )

    codes.mark_used(code)

    session, new_refresh_token = issue_session_and_refresh_token(
        subject_id=subject.subject_id,
        tenant_id=tenant_id,
        client_id=client.client_id,
        requested_scopes=auth_code.scopes,
        session_store=session_store,
        token_manager=token_manager,
        session_ttl_seconds=session_ttl_seconds,
    )
    roles = authorization_engine.resolve_roles(
        subject_id=subject.subject_id,
        tenant_id=tenant_id,
    )

    permissions = authorization_engine.resolve_permissions(
        subject_id=subject.subject_id,
        tenant_id=tenant_id,
    )

    filtered_scopes = scope_policy.filter_scopes(
        requested_scopes=auth_code.scopes,
        permissions=permissions,
    )

    if filtered_scopes != auth_code.scopes:
        raise InvalidGrantError("Requested scope not permitted by role")

    return _issue_tokens_for_session(
        subject=subject,
        client=client,
        scopes=filtered_scopes,
        session=session,
        roles=roles,
        refresh_token=new_refresh_token,
        auth_code=auth_code,
        token_manager=token_manager,
        access_token_audience=access_token_audience,
    )


def _validate_authorization_code(
    *,
    code: str,
    redirect_uri: str,
    client: OAuthClient,
    codes: AuthorizationCodeStore,
    code_verifier: str,
) -> AuthorizationCode:
    auth_code = codes.get(code)
    if not auth_code:
        raise InvalidGrantError("Invalid code")

    if auth_code.used:
        raise InvalidGrantError("Code already used")

    if auth_code.is_expired():
        raise InvalidGrantError("Code expired")

    if auth_code.client_id != client.client_id:
        raise InvalidGrantError("Code not issued to this client")

    if auth_code.redirect_uri != redirect_uri:
        raise InvalidGrantError("Redirect URI mismatch")

    if not verify_pkce(
        code_verifier=code_verifier,
        code_challenge=auth_code.pkce.code_challenge,
        code_challenge_method=auth_code.pkce.code_challenge_method,
    ):
        raise InvalidGrantError("PKCE verification failed")

    return auth_code


# ============================================================
# Refresh Token Flow
# ============================================================


def _handle_refresh_token(
    *,
    refresh_token: str | None,
    session_store: SessionStore,
    token_manager: TokenKeyManager,
    access_token_audience: str,
    session_ttl_seconds: int,
    scope_policy: ScopePolicy,
    authorization_engine: AuthorizationEngine,
) -> TokenResponse:
    if refresh_token is None:
        raise InvalidRequestError("Missing refresh_token")

    session, new_refresh_token = rotate_refresh_token(
        refresh_token=refresh_token,
        session_store=session_store,
        token_manager=token_manager,
        session_ttl_seconds=session_ttl_seconds,
    )
    roles = authorization_engine.resolve_roles(
        subject_id=session.subject_id,
        tenant_id=session.tenant_id,
    )

    permissions = authorization_engine.resolve_permissions(
        subject_id=session.subject_id,
        tenant_id=session.tenant_id,
    )

    filtered_scopes = scope_policy.filter_scopes(
        requested_scopes=session.requested_scopes,
        permissions=permissions,
    )

    access_token = token_manager.issue_jwt(
        subject=session.subject_id,
        audience=access_token_audience,
        extra_claims={
            "scp": list(filtered_scopes),
            "cid": session.client_id,
            "tid": session.tenant_id,
            "roles": list(roles),
            "sid": session.session_id,
            "ver": session.version,
            "acr": session.acr,
            "amr": list(session.amr),
        },
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
    )


def _handle_password_token(
    *,
    client_id: str,
    tenant_id: str,
    username: str | None,
    password: str | None,
    requested_scopes: set[str] | None,
    clients: ClientRegistry,
    session_store: SessionStore,
    token_manager: TokenKeyManager,
    access_token_audience: str,
    session_ttl_seconds: int,
    scope_policy: ScopePolicy,
    authorization_engine: AuthorizationEngine,
    authorization_header: str | None,
    form_client_secret: str | None,
    client_assertion: str | None,
    client_assertion_type: str | None,
    token_endpoint: str,
    password_authenticator: PasswordAuthenticator | None,
) -> TokenResponse:
    if not username or not password:
        raise InvalidRequestError("Missing username/password")

    if password_authenticator is None:
        raise UnsupportedGrantTypeError("Password grant is not enabled")

    client = clients.get_client(client_id)
    if not client:
        raise InvalidClientError("Unknown client")

    authenticate_client(
        client=client,
        authorization_header=authorization_header,
        form_client_id=client_id,
        form_client_secret=form_client_secret,
        client_assertion=client_assertion,
        client_assertion_type=client_assertion_type,
        token_endpoint=token_endpoint,
    )

    subject = password_authenticator.authenticate(
        username=username,
        password=password,
        tenant_id=tenant_id,
    )
    if not subject:
        raise InvalidGrantError("Invalid resource owner credentials")

    if tenant_id not in subject.tenants:
        raise InvalidGrantError("Subject not in tenant")

    scopes = requested_scopes or {"openid"}
    client.validate_scopes(scopes)

    session, refresh_token = issue_session_and_refresh_token(
        subject_id=subject.subject_id,
        tenant_id=tenant_id,
        client_id=client.client_id,
        requested_scopes=scopes,
        session_store=session_store,
        token_manager=token_manager,
        session_ttl_seconds=session_ttl_seconds,
    )

    return _issue_tokens_for_subject_session(
        subject=subject,
        client=client,
        scopes=scopes,
        session=session,
        refresh_token=refresh_token,
        token_manager=token_manager,
        access_token_audience=access_token_audience,
        authorization_engine=authorization_engine,
        scope_policy=scope_policy,
    )


def _handle_api_key_token(
    *,
    client_id: str,
    tenant_id: str,
    api_key: str | None,
    requested_scopes: set[str] | None,
    clients: ClientRegistry,
    session_store: SessionStore,
    token_manager: TokenKeyManager,
    access_token_audience: str,
    session_ttl_seconds: int,
    scope_policy: ScopePolicy,
    authorization_engine: AuthorizationEngine,
    authorization_header: str | None,
    form_client_secret: str | None,
    client_assertion: str | None,
    client_assertion_type: str | None,
    token_endpoint: str,
    api_key_authenticator: APIKeyAuthenticator | None,
) -> TokenResponse:
    if not api_key:
        raise InvalidRequestError("Missing api_key")

    if api_key_authenticator is None:
        raise UnsupportedGrantTypeError("API key grant is not enabled")

    client = clients.get_client(client_id)
    if not client:
        raise InvalidClientError("Unknown client")

    authenticate_client(
        client=client,
        authorization_header=authorization_header,
        form_client_id=client_id,
        form_client_secret=form_client_secret,
        client_assertion=client_assertion,
        client_assertion_type=client_assertion_type,
        token_endpoint=token_endpoint,
    )

    subject = api_key_authenticator.authenticate(
        api_key=api_key,
        tenant_id=tenant_id,
    )
    if not subject:
        raise InvalidGrantError("Invalid API key")

    if tenant_id not in subject.tenants:
        raise InvalidGrantError("Subject not in tenant")

    scopes = requested_scopes or {"openid"}
    client.validate_scopes(scopes)

    session, refresh_token = issue_session_and_refresh_token(
        subject_id=subject.subject_id,
        tenant_id=tenant_id,
        client_id=client.client_id,
        requested_scopes=scopes,
        session_store=session_store,
        token_manager=token_manager,
        session_ttl_seconds=session_ttl_seconds,
    )

    return _issue_tokens_for_subject_session(
        subject=subject,
        client=client,
        scopes=scopes,
        session=session,
        refresh_token=refresh_token,
        token_manager=token_manager,
        access_token_audience=access_token_audience,
        authorization_engine=authorization_engine,
        scope_policy=scope_policy,
    )


# ============================================================
# Shared Token Issuance
# ============================================================


def _issue_tokens_for_session(
    *,
    subject: Subject,
    client: OAuthClient,
    scopes: set[str],
    session: Session,
    roles: set[str],
    refresh_token: str,
    auth_code: AuthorizationCode,
    token_manager: TokenKeyManager,
    access_token_audience: str,
) -> TokenResponse:
    access_token = token_manager.issue_jwt(
        subject=subject.subject_id,
        audience=access_token_audience,
        extra_claims={
            "scp": list(scopes),
            "cid": client.client_id,
            "tid": session.tenant_id,
            "roles": list(roles),
            "sid": session.session_id,
            "ver": session.version,
            "acr": session.acr,
            "amr": list(session.amr),
        },
    )

    id_claims = build_id_token_claims(
        ctx=TokenRequestContext(
            client=client,
            subject=subject,
            scopes=scopes,
            nonce=auth_code.nonce,
            auth_time=auth_code.issued_at,
        ),
        issuer=token_manager._config.issuer,
        ttl_seconds=token_manager._config.access_token_ttl_seconds,
    )

    id_token = token_manager.issue_jwt(
        subject=subject.subject_id,
        audience=client.client_id,
        extra_claims={**id_claims, "tid": session.tenant_id, "acr": session.acr, "amr": list(session.amr)},
    )

    return TokenResponse(
        access_token=access_token,
        id_token=id_token,
        refresh_token=refresh_token,
    )


def _issue_tokens_for_subject_session(
    *,
    subject: Subject,
    client: OAuthClient,
    scopes: set[str],
    session: Session,
    refresh_token: str,
    token_manager: TokenKeyManager,
    access_token_audience: str,
    authorization_engine: AuthorizationEngine,
    scope_policy: ScopePolicy,
) -> TokenResponse:
    roles = authorization_engine.resolve_roles(
        subject_id=subject.subject_id,
        tenant_id=session.tenant_id,
    )

    permissions = authorization_engine.resolve_permissions(
        subject_id=subject.subject_id,
        tenant_id=session.tenant_id,
    )

    filtered_scopes = scope_policy.filter_scopes(
        requested_scopes=scopes,
        permissions=permissions,
    )

    if filtered_scopes != scopes:
        raise InvalidGrantError("Requested scope not permitted by role")

    access_token = token_manager.issue_jwt(
        subject=subject.subject_id,
        audience=access_token_audience,
        extra_claims={
            "scp": list(filtered_scopes),
            "cid": client.client_id,
            "tid": session.tenant_id,
            "roles": list(roles),
            "sid": session.session_id,
            "ver": session.version,
            "acr": session.acr,
            "amr": list(session.amr),
        },
    )

    id_claims = build_id_token_claims(
        ctx=TokenRequestContext(
            client=client,
            subject=subject,
            scopes=filtered_scopes,
            nonce=None,
            auth_time=datetime.now(tz=UTC),
        ),
        issuer=token_manager._config.issuer,
        ttl_seconds=token_manager._config.access_token_ttl_seconds,
    )

    id_token = token_manager.issue_jwt(
        subject=subject.subject_id,
        audience=client.client_id,
        extra_claims={**id_claims, "tid": session.tenant_id, "acr": session.acr, "amr": list(session.amr)},
    )

    return TokenResponse(
        access_token=access_token,
        id_token=id_token,
        refresh_token=refresh_token,
    )

