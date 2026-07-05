from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Literal, Protocol
from urllib.parse import urlencode

from astraauth.idp.models import (
    ClaimAttributeMapping,
    ExternalIdentityLink,
    FederationAuditRecord,
    OIDCAuthorizationRequest,
    OIDCCallbackPayload,
    OIDCExternalProfile,
    OIDCFederationResult,
    OIDCIDTokenClaims,
    OIDCLoginState,
    OIDCProviderConfig,
    OIDCProviderMetadata,
    OIDCTokenResponse,
    OIDCUserInfo,
)
from astraauth.idp.store import (
    ClaimAttributeMappingRepository,
    FederationAuditRepository,
    GroupRoleMappingRepository,
    IdentityLinkRepository,
    OIDCLoginStateRepository,
)


class OIDCMetadataClient(Protocol):
    def fetch_metadata(self, *, discovery_url: str) -> dict[str, object]: ...


class OIDCCodeExchangeClient(Protocol):
    def exchange_code(
        self,
        *,
        provider: OIDCProviderConfig,
        metadata: OIDCProviderMetadata,
        code: str,
        redirect_uri: str,
        code_verifier: str,
    ) -> OIDCTokenResponse: ...

    def fetch_userinfo(
        self,
        *,
        provider: OIDCProviderConfig,
        metadata: OIDCProviderMetadata,
        token_response: OIDCTokenResponse,
    ) -> OIDCUserInfo: ...

    def validate_id_token(
        self,
        *,
        provider: OIDCProviderConfig,
        metadata: OIDCProviderMetadata,
        token_response: OIDCTokenResponse,
        expected_nonce: str,
    ) -> OIDCIDTokenClaims: ...


class FederationMappingError(Exception):
    pass


class OIDCProtocolError(Exception):
    pass


def discover_provider_metadata(
    *,
    provider: OIDCProviderConfig,
    metadata_client: OIDCMetadataClient,
) -> OIDCProviderMetadata:
    discovery_url = (
        provider.discovery_url or f"{provider.issuer.rstrip('/')}/.well-known/openid-configuration"
    )
    raw = metadata_client.fetch_metadata(discovery_url=discovery_url)
    metadata = OIDCProviderMetadata(
        issuer=str(raw["issuer"]),
        authorization_endpoint=str(raw["authorization_endpoint"]),
        token_endpoint=str(raw["token_endpoint"]),
        jwks_uri=str(raw["jwks_uri"]),
        userinfo_endpoint=str(raw["userinfo_endpoint"])
        if raw.get("userinfo_endpoint") is not None
        else None,
        scopes_supported=_tupleify_strings(raw.get("scopes_supported")),
        response_types_supported=_tupleify_strings(
            raw.get("response_types_supported"), default=("code",)
        ),
        subject_types_supported=_tupleify_strings(
            raw.get("subject_types_supported"), default=("public",)
        ),
        id_token_signing_alg_values_supported=_tupleify_strings(
            raw.get("id_token_signing_alg_values_supported"),
            default=("RS256",),
        ),
    )
    if metadata.issuer.rstrip("/") != provider.issuer.rstrip("/"):
        raise OIDCProtocolError("issuer_mismatch")
    return metadata


def begin_oidc_login(
    *,
    provider: OIDCProviderConfig,
    metadata: OIDCProviderMetadata,
    tenant_id: str,
    redirect_uri: str,
    state_repository: OIDCLoginStateRepository,
    audit_repository: FederationAuditRepository | None = None,
    ttl_seconds: int = 300,
) -> tuple[OIDCLoginState, OIDCAuthorizationRequest]:
    code_verifier = _generate_token(48)
    nonce = _generate_token(24)
    state = OIDCLoginState.issue(
        provider_id=provider.provider_id,
        tenant_id=tenant_id,
        redirect_uri=redirect_uri,
        code_verifier=code_verifier,
        nonce=nonce,
        ttl_seconds=ttl_seconds,
    )
    state_repository.save(state)
    request = OIDCAuthorizationRequest(
        authorization_endpoint=metadata.authorization_endpoint,
        client_id=provider.client_id,
        redirect_uri=redirect_uri,
        scope=" ".join(provider.scopes),
        response_type="code",
        state=state.state_id,
        nonce=nonce,
        code_challenge=_pkce_challenge(code_verifier),
    )
    if audit_repository is not None:
        audit_repository.save(
            FederationAuditRecord.create(
                event_type="oidc.login.start",
                provider_id=provider.provider_id,
                tenant_id=tenant_id,
                status="started",
                state_id=state.state_id,
                details={"redirect_uri": redirect_uri},
            )
        )
    return state, request


def build_authorization_url(request: OIDCAuthorizationRequest) -> str:
    return f"{request.authorization_endpoint}?{urlencode(request.__dict__)}"


def complete_oidc_callback(
    *,
    provider: OIDCProviderConfig,
    metadata: OIDCProviderMetadata,
    tenant_id: str,
    callback: OIDCCallbackPayload,
    state_repository: OIDCLoginStateRepository,
    exchange_client: OIDCCodeExchangeClient,
    audit_repository: FederationAuditRepository | None = None,
) -> OIDCExternalProfile:
    state = state_repository.get(callback.state)
    if state is None:
        _record_callback_audit(
            audit_repository,
            provider_id=provider.provider_id,
            tenant_id=tenant_id,
            status="failed",
            state_id=callback.state,
            reason="invalid_state",
        )
        raise OIDCProtocolError("invalid_state")
    if state.is_expired():
        state_repository.delete(state.state_id)
        _record_callback_audit(
            audit_repository,
            provider_id=provider.provider_id,
            tenant_id=tenant_id,
            status="failed",
            state_id=state.state_id,
            reason="expired_state",
        )
        raise OIDCProtocolError("expired_state")
    if state.provider_id != provider.provider_id or state.tenant_id != tenant_id:
        state_repository.delete(state.state_id)
        _record_callback_audit(
            audit_repository,
            provider_id=provider.provider_id,
            tenant_id=tenant_id,
            status="failed",
            state_id=state.state_id,
            reason="state_scope_mismatch",
        )
        raise OIDCProtocolError("state_scope_mismatch")
    if state.redirect_uri != callback.redirect_uri:
        state_repository.delete(state.state_id)
        _record_callback_audit(
            audit_repository,
            provider_id=provider.provider_id,
            tenant_id=tenant_id,
            status="failed",
            state_id=state.state_id,
            reason="redirect_uri_mismatch",
        )
        raise OIDCProtocolError("redirect_uri_mismatch")
    state_repository.delete(state.state_id)

    try:
        userinfo = _exchange_and_validate_callback(
            provider=provider,
            metadata=metadata,
            callback=callback,
            state=state,
            exchange_client=exchange_client,
        )
    except Exception as exc:
        _record_callback_audit(
            audit_repository,
            provider_id=provider.provider_id,
            tenant_id=tenant_id,
            status="failed",
            state_id=state.state_id,
            reason=str(exc),
        )
        raise
    _record_callback_audit(
        audit_repository,
        provider_id=provider.provider_id,
        tenant_id=tenant_id,
        status="succeeded",
        state_id=state.state_id,
        external_subject=userinfo.subject,
    )
    return OIDCExternalProfile(
        provider_id=provider.provider_id,
        external_subject=userinfo.subject,
        tenant_id=tenant_id,
        claims=userinfo.claims,
        email=userinfo.email,
        email_verified=userinfo.email_verified,
    )


def resolve_roles_from_profile(
    *,
    profile: OIDCExternalProfile,
    mapping_repository: GroupRoleMappingRepository,
) -> tuple[str, ...]:
    mappings = mapping_repository.list_for_provider(
        provider_id=profile.provider_id,
        tenant_id=profile.tenant_id,
    )
    roles = {mapping.role_name for mapping in mappings if mapping.external_group in profile.groups}
    return tuple(sorted(roles))


def map_profile_to_subject_attributes(
    *,
    profile: OIDCExternalProfile,
    mapping_repository: ClaimAttributeMappingRepository,
) -> dict[str, str | int | float | bool]:
    mappings = mapping_repository.list_for_provider(
        provider_id=profile.provider_id,
        tenant_id=profile.tenant_id,
    )
    attributes: dict[str, str | int | float | bool] = {}
    for mapping in mappings:
        if mapping.claim_name not in profile.claims:
            if mapping.required:
                raise FederationMappingError(f"missing_required_claim:{mapping.claim_name}")
            continue
        transformed = _transform_claim(profile.claims[mapping.claim_name], mapping)
        if transformed is not None:
            attributes[mapping.attribute_name] = transformed
    return attributes


def link_or_update_external_identity(
    *,
    subject_id: str,
    profile: OIDCExternalProfile,
    link_repository: IdentityLinkRepository,
) -> ExternalIdentityLink:
    existing = link_repository.get(
        provider_id=profile.provider_id,
        external_subject=profile.external_subject,
        tenant_id=profile.tenant_id,
    )
    if existing is None:
        link = ExternalIdentityLink.create(
            provider_id=profile.provider_id,
            external_subject=profile.external_subject,
            subject_id=subject_id,
            tenant_id=profile.tenant_id,
            email=profile.email,
            email_verified=profile.email_verified,
            claims=profile.claims,
        )
    else:
        if existing.subject_id != subject_id:
            raise FederationMappingError("external_identity_already_linked")
        link = existing.refresh_claims(
            email=profile.email,
            email_verified=profile.email_verified,
            claims=profile.claims,
        )
    link_repository.save(link)
    return link


def federate_oidc_profile(
    *,
    subject_id: str,
    profile: OIDCExternalProfile,
    link_repository: IdentityLinkRepository,
    group_role_mapping_repository: GroupRoleMappingRepository,
    claim_attribute_mapping_repository: ClaimAttributeMappingRepository,
) -> OIDCFederationResult:
    link = link_or_update_external_identity(
        subject_id=subject_id,
        profile=profile,
        link_repository=link_repository,
    )
    roles = resolve_roles_from_profile(
        profile=profile,
        mapping_repository=group_role_mapping_repository,
    )
    attributes = map_profile_to_subject_attributes(
        profile=profile,
        mapping_repository=claim_attribute_mapping_repository,
    )
    return OIDCFederationResult(
        subject_id=subject_id,
        tenant_id=profile.tenant_id,
        provider_id=profile.provider_id,
        external_subject=profile.external_subject,
        resolved_roles=roles,
        subject_attributes=attributes,
        link=link,
    )


def _transform_claim(
    value: object, mapping: ClaimAttributeMapping
) -> str | int | float | bool | None:
    if mapping.transform == "string":
        return _stringify(value)
    if mapping.transform == "lower":
        rendered = _stringify(value)
        return rendered.lower() if rendered is not None else None
    if mapping.transform == "bool":
        if isinstance(value, bool):
            return value
        rendered = _stringify(value)
        if rendered is None:
            return None
        return rendered.lower() in {"1", "true", "yes", "on"}
    if mapping.transform == "csv":
        if isinstance(value, tuple):
            return ",".join(str(item) for item in value)
        return _stringify(value)
    raise FederationMappingError(f"unsupported_transform:{mapping.transform}")


def _stringify(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, tuple):
        return ",".join(str(item) for item in value)
    return str(value)


def _tupleify_strings(value: object, default: tuple[str, ...] = ()) -> tuple[str, ...]:
    if value is None:
        return default
    if isinstance(value, tuple):
        return tuple(str(item) for item in value)
    if isinstance(value, list):
        return tuple(str(item) for item in value)
    if isinstance(value, str):
        return (value,)
    return default


def _exchange_and_validate_callback(
    *,
    provider: OIDCProviderConfig,
    metadata: OIDCProviderMetadata,
    callback: OIDCCallbackPayload,
    state: OIDCLoginState,
    exchange_client: OIDCCodeExchangeClient,
) -> OIDCUserInfo:
    token_response = exchange_client.exchange_code(
        provider=provider,
        metadata=metadata,
        code=callback.code,
        redirect_uri=callback.redirect_uri,
        code_verifier=state.code_verifier,
    )
    id_token_claims = exchange_client.validate_id_token(
        provider=provider,
        metadata=metadata,
        token_response=token_response,
        expected_nonce=state.nonce,
    )
    userinfo = exchange_client.fetch_userinfo(
        provider=provider,
        metadata=metadata,
        token_response=token_response,
    )
    if id_token_claims.issuer.rstrip("/") != metadata.issuer.rstrip("/"):
        raise OIDCProtocolError("id_token_issuer_mismatch")
    if provider.client_id not in id_token_claims.audience:
        raise OIDCProtocolError("id_token_audience_mismatch")
    if id_token_claims.subject != userinfo.subject:
        raise OIDCProtocolError("subject_mismatch")
    if id_token_claims.nonce != state.nonce:
        raise OIDCProtocolError("nonce_mismatch")
    return userinfo


def _record_callback_audit(
    audit_repository: FederationAuditRepository | None,
    *,
    provider_id: str,
    tenant_id: str,
    status: Literal["started", "succeeded", "failed"],
    state_id: str | None,
    reason: str | None = None,
    external_subject: str | None = None,
) -> None:
    if audit_repository is None:
        return
    audit_repository.save(
        FederationAuditRecord.create(
            event_type="oidc.callback" if status != "started" else "oidc.login.start",
            provider_id=provider_id,
            tenant_id=tenant_id,
            status=status,
            state_id=state_id,
            reason=reason,
            external_subject=external_subject,
        )
    )


def _generate_token(length: int) -> str:
    return secrets.token_urlsafe(length)


def _pkce_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
