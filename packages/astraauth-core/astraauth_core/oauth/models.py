from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from astraauth_core.oauth.errors import InvalidRequestError

# ============================================================
# Subject (Resource Owner / End-User)
# ============================================================


@dataclass(frozen=True)
class Subject:
    """
    Represents the authenticated end-user (or principal).
    """

    subject_id: str
    tenants: set[str] = field(default_factory=set)
    username: str | None = None
    email: str | None = None


# ============================================================
# OAuth Client
# ============================================================


ClientType = Literal["public", "confidential"]

ClientAuthMethod = Literal[
    "none",
    "client_secret_basic",
    "client_secret_post",
    "private_key_jwt",
]


@dataclass
class OAuthClient:
    client_id: str
    redirect_uris: set[str]
    allowed_scopes: set[str]

    allowed_tenants: set[str] | None = None

    client_type: ClientType = "public"
    auth_method: ClientAuthMethod = "none"
    client_secret: str | None = None

    # PKCE policy
    require_pkce: bool = True

    # JWT client auth
    jwks: dict[str, Any] | None = None
    jwks_uri: str | None = None
    token_endpoint_auth_signing_alg: str | None = "RS256"

    # ----------------------------------------------------------
    # Redirect URI Validation
    # ----------------------------------------------------------

    def validate_redirect_uri(self, redirect_uri: str) -> None:
        if redirect_uri not in self.redirect_uris:
            raise InvalidRequestError("Invalid redirect_uri")

    # ----------------------------------------------------------
    # Scope Validation
    # ----------------------------------------------------------

    def validate_scopes(self, scopes: set[str]) -> None:
        if not scopes.issubset(self.allowed_scopes):
            raise InvalidRequestError("Invalid scope requested")

    # ----------------------------------------------------------
    # Tenant Validation
    # ----------------------------------------------------------

    def validate_tenant(self, tenant_id: str) -> None:
        if self.allowed_tenants is None:
            return

        if tenant_id not in self.allowed_tenants:
            raise InvalidRequestError("Client not allowed for tenant")


# ============================================================
# PKCE Parameters
# ============================================================


@dataclass(frozen=True)
class PKCEParams:
    """
    Holds PKCE parameters for OAuth 2.1 Authorization Code flow.
    """

    code_challenge: str
    code_challenge_method: Literal["S256"]  # "S256" only in OAuth 2.1

    def validate(self) -> None:
        if self.code_challenge_method != "S256":
            raise ValueError("Only S256 PKCE method is allowed in OAuth 2.1")
        if not self.code_challenge:
            raise ValueError("code_challenge must not be empty")


# ============================================================
# Authorization Code
# ============================================================


@dataclass
class AuthorizationCode:
    """
    Represents an issued authorization code (one-time use).
    """

    code: str
    client_id: str
    tenant_id: str | None
    subject_id: str
    redirect_uri: str
    scopes: set[str]
    issued_at: datetime
    expires_at: datetime
    pkce: PKCEParams
    nonce: str | None = None
    used: bool = False

    @classmethod
    def issue(
        cls,
        *,
        client_id: str,
        tenant_id: str,
        subject_id: str,
        redirect_uri: str,
        scopes: set[str],
        ttl_seconds: int,
        pkce: PKCEParams,
        nonce: str | None = None,
    ) -> AuthorizationCode:
        now = datetime.now(tz=UTC)
        code = secrets.token_urlsafe(32)
        return cls(
            code=code,
            client_id=client_id,
            tenant_id=tenant_id,
            subject_id=subject_id,
            redirect_uri=redirect_uri,
            scopes=scopes,
            issued_at=now,
            expires_at=now.replace(microsecond=0) + timedelta(seconds=ttl_seconds),
            pkce=pkce,
            nonce=nonce,
            used=False,
        )

    def is_expired(self) -> bool:
        return datetime.now(tz=UTC) >= self.expires_at

    def mark_used(self) -> None:
        self.used = True


# ============================================================
# Token Request Context
# ============================================================


@dataclass(frozen=True)
class TokenRequestContext:
    """
    Captures the validated context for a token exchange.
    """

    client: OAuthClient
    subject: Subject
    scopes: set[str]
    nonce: str | None
    auth_time: datetime | None = None
