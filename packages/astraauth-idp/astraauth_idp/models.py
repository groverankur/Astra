from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import uuid4

ClaimValue = str | int | float | bool | tuple[str, ...]


@dataclass(frozen=True)
class OIDCProviderConfig:
    provider_id: str
    issuer: str
    client_id: str
    client_secret: str | None = None
    discovery_url: str | None = None
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    userinfo_endpoint: str | None = None
    jwks_uri: str | None = None
    scopes: tuple[str, ...] = ("openid", "profile", "email")


@dataclass(frozen=True)
class OIDCProviderMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str | None = None
    scopes_supported: tuple[str, ...] = ()
    response_types_supported: tuple[str, ...] = ("code",)
    subject_types_supported: tuple[str, ...] = ("public",)
    id_token_signing_alg_values_supported: tuple[str, ...] = ("RS256",)


@dataclass(frozen=True)
class OIDCLoginState:
    state_id: str
    provider_id: str
    tenant_id: str
    redirect_uri: str
    code_verifier: str
    nonce: str
    created_at: datetime
    expires_at: datetime

    @classmethod
    def issue(
        cls,
        *,
        provider_id: str,
        tenant_id: str,
        redirect_uri: str,
        code_verifier: str,
        nonce: str,
        ttl_seconds: int = 300,
    ) -> OIDCLoginState:
        now = datetime.now(tz=UTC)
        return cls(
            state_id=str(uuid4()),
            provider_id=provider_id,
            tenant_id=tenant_id,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
            nonce=nonce,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )

    def is_expired(self, *, now: datetime | None = None) -> bool:
        effective_now = now or datetime.now(tz=UTC)
        return effective_now >= self.expires_at


@dataclass(frozen=True)
class OIDCAuthorizationRequest:
    authorization_endpoint: str
    client_id: str
    redirect_uri: str
    scope: str
    response_type: str
    state: str
    nonce: str
    code_challenge: str
    code_challenge_method: str = "S256"


@dataclass(frozen=True)
class OIDCTokenResponse:
    access_token: str
    token_type: str
    expires_in: int | None = None
    id_token: str | None = None
    refresh_token: str | None = None
    scope: str | None = None


@dataclass(frozen=True)
class OIDCIDTokenClaims:
    issuer: str
    subject: str
    audience: tuple[str, ...]
    nonce: str | None = None
    issued_at: datetime | None = None
    expires_at: datetime | None = None
    auth_time: datetime | None = None
    acr: str | None = None
    amr: tuple[str, ...] = ()


@dataclass(frozen=True)
class OIDCUserInfo:
    subject: str
    claims: dict[str, ClaimValue]
    email: str | None = None
    email_verified: bool | None = None


@dataclass(frozen=True)
class OIDCCallbackPayload:
    code: str
    state: str
    redirect_uri: str


@dataclass(frozen=True)
class ExternalIdentityLink:
    provider_id: str
    external_subject: str
    subject_id: str
    tenant_id: str
    created_at: datetime
    updated_at: datetime
    email: str | None = None
    email_verified: bool | None = None
    claims: dict[str, ClaimValue] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        *,
        provider_id: str,
        external_subject: str,
        subject_id: str,
        tenant_id: str,
        email: str | None = None,
        email_verified: bool | None = None,
        claims: dict[str, ClaimValue] | None = None,
    ) -> ExternalIdentityLink:
        now = datetime.now(tz=UTC)
        return cls(
            provider_id=provider_id,
            external_subject=external_subject,
            subject_id=subject_id,
            tenant_id=tenant_id,
            created_at=now,
            updated_at=now,
            email=email,
            email_verified=email_verified,
            claims=claims or {},
        )

    def refresh_claims(
        self,
        *,
        email: str | None = None,
        email_verified: bool | None = None,
        claims: dict[str, ClaimValue] | None = None,
    ) -> ExternalIdentityLink:
        return ExternalIdentityLink(
            provider_id=self.provider_id,
            external_subject=self.external_subject,
            subject_id=self.subject_id,
            tenant_id=self.tenant_id,
            created_at=self.created_at,
            updated_at=datetime.now(tz=UTC),
            email=email if email is not None else self.email,
            email_verified=email_verified if email_verified is not None else self.email_verified,
            claims=claims or dict(self.claims),
        )


@dataclass(frozen=True)
class OIDCExternalProfile:
    provider_id: str
    external_subject: str
    tenant_id: str
    claims: dict[str, ClaimValue]
    email: str | None = None
    email_verified: bool | None = None

    @property
    def groups(self) -> tuple[str, ...]:
        raw = self.claims.get("groups")
        if isinstance(raw, tuple):
            return raw
        if isinstance(raw, list):
            return tuple(str(item) for item in raw)
        if isinstance(raw, str):
            return (raw,)
        return ()


@dataclass(frozen=True)
class GroupRoleMapping:
    provider_id: str
    tenant_id: str
    external_group: str
    role_name: str


@dataclass(frozen=True)
class ClaimAttributeMapping:
    provider_id: str
    tenant_id: str
    claim_name: str
    attribute_name: str
    required: bool = False
    transform: Literal["string", "lower", "bool", "csv"] = "string"


@dataclass(frozen=True)
class OIDCFederationResult:
    subject_id: str
    tenant_id: str
    provider_id: str
    external_subject: str
    resolved_roles: tuple[str, ...]
    subject_attributes: dict[str, str | int | float | bool]
    link: ExternalIdentityLink


@dataclass(frozen=True)
class FederationAuditRecord:
    audit_id: str
    event_type: str
    provider_id: str
    tenant_id: str
    status: Literal["started", "succeeded", "failed"]
    created_at: datetime
    state_id: str | None = None
    client_id: str | None = None
    subject_id: str | None = None
    external_subject: str | None = None
    reason: str | None = None
    details: dict[str, str | int | float | bool] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        *,
        event_type: str,
        provider_id: str,
        tenant_id: str,
        status: Literal["started", "succeeded", "failed"],
        state_id: str | None = None,
        client_id: str | None = None,
        subject_id: str | None = None,
        external_subject: str | None = None,
        reason: str | None = None,
        details: dict[str, str | int | float | bool] | None = None,
    ) -> FederationAuditRecord:
        return cls(
            audit_id=str(uuid4()),
            event_type=event_type,
            provider_id=provider_id,
            tenant_id=tenant_id,
            status=status,
            created_at=datetime.now(tz=UTC),
            state_id=state_id,
            client_id=client_id,
            subject_id=subject_id,
            external_subject=external_subject,
            reason=reason,
            details=details or {},
        )



