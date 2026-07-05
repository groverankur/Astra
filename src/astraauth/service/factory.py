from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import HTTPHandler, HTTPSHandler, Request, build_opener

from astraauth_plugins import GeoSignalPlugin, RiskSignalPlugin
from joserfc import jwk, jwt

from astraauth.core.adapters.oauth_http import OAuthHTTPAdapter
from astraauth.core.authorization.engine import AuthorizationEngine
from astraauth.core.authorization.models import Role, TenantRoleAssignment
from astraauth.core.authorization.scope_policy import DefaultScopePolicy
from astraauth.core.authorization.store import InMemoryAssignmentStore, InMemoryRoleStore
from astraauth.core.config import (
    AuthConfig,
    OIDCProviderSettings,
    RelationalStoreConfig,
    enforce_private_file_permissions,
    ensure_private_directory,
)
from astraauth.core.events.inmemory import InMemoryEventBus
from astraauth.core.mfa import (
    EmailOTPCodeStore,
    EmailOTPFactorStore,
    InMemoryEmailOTPCodeStore,
    InMemoryEmailOTPFactorStore,
    InMemoryMFAChallengeStore,
    InMemoryTOTPFactorStore,
    MFAChallengeStore,
    OTPAuthTOTPProvider,
    SQLEmailOTPCodeStore,
    SQLEmailOTPFactorStore,
    SQLMFAChallengeStore,
    SQLTOTPFactorStore,
    TOTPFactorStore,
    activate_email_otp_factor,
    activate_totp_factor,
    enroll_email_otp_factor,
    enroll_totp_factor,
    upgrade_session_with_verified_challenge,
)
from astraauth.core.oauth.api_key import (
    APIKeyRecord,
    InMemoryAPIKeyAuthenticator,
    Sha256APIKeyHasher,
    digest_api_key,
)
from astraauth.core.oauth.inmemory import (
    InMemoryAuthorizationCodeStore,
    InMemoryClientRegistry,
    InMemorySubjectDirectory,
)
from astraauth.core.oauth.models import OAuthClient, Subject, TokenRequestContext
from astraauth.core.oauth.oidc import build_id_token_claims
from astraauth.core.oauth.password import (
    InMemoryPasswordAuthenticator,
    MultiSchemePasswordVerifier,
    PasswordRecord,
    hash_password,
)
from astraauth.core.oauth.services import TokenResponse
from astraauth.core.plugins import (
    InMemoryTenantPluginRegistryStore,
    SQLTenantPluginRegistryStore,
    TenantPluginRegistryStore,
)
from astraauth.core.security import InMemoryThrottleStore, SharedThrottleStore, ThrottleStore
from astraauth.core.sessions import SQLSessionStore
from astraauth.core.sessions.models import Session
from astraauth.core.sessions.services import issue_session_and_refresh_token
from astraauth.core.sessions.store import InMemorySessionStore, SessionStore
from astraauth.core.token.token_manager import TokenKeyManager
from astraauth.idp import (
    ClaimAttributeMapping,
    FederationAuditRecord,
    FederationAuditRepository,
    GroupRoleMapping,
    IdentityLinkRepository,
    InMemoryClaimAttributeMappingRepository,
    InMemoryFederationAuditRepository,
    InMemoryGroupRoleMappingRepository,
    InMemoryIdentityLinkRepository,
    InMemoryOIDCLoginStateRepository,
    OIDCCallbackPayload,
    OIDCCodeExchangeClient,
    OIDCExternalProfile,
    OIDCFederationResult,
    OIDCIDTokenClaims,
    OIDCLoginStateRepository,
    OIDCMetadataClient,
    OIDCProtocolError,
    OIDCProviderConfig,
    OIDCProviderMetadata,
    OIDCTokenResponse,
    OIDCUserInfo,
    SQLClaimAttributeMappingRepository,
    SQLFederationAuditRepository,
    SQLGroupRoleMappingRepository,
    SQLIdentityLinkRepository,
    SQLOIDCLoginStateRepository,
    begin_oidc_login,
    build_authorization_url,
    complete_oidc_callback,
    discover_provider_metadata,
    federate_oidc_profile,
)
from astraauth.plugins import PluginRuntime, PluginTrustPolicy
from astraauth.plugins.contracts import HookName, Plugin, PluginAuditRecord, PluginManifest
from astraauth.service.observability import next_correlation_id, record_event, record_metric
from astraauth.webauthn import (
    InMemoryWebAuthnAuthenticationStateRepository,
    InMemoryWebAuthnCredentialRepository,
    InMemoryWebAuthnRegistrationStateRepository,
    SQLWebAuthnAuthenticationStateRepository,
    SQLWebAuthnCredentialRepository,
    SQLWebAuthnRegistrationStateRepository,
    WebAuthnVerifier,
    begin_authentication_for_mfa,
    begin_registration,
    build_default_webauthn_verifier,
    finish_authentication_for_mfa,
    finish_registration,
)
from astraauth.webauthn.store import (
    WebAuthnAuthenticationStateRepository,
    WebAuthnCredentialRepository,
    WebAuthnRegistrationStateRepository,
)


class ServiceHookRunner:
    def __init__(self, runtime: PluginRuntime) -> None:
        self._runtime = runtime

    def run_hook(
        self,
        *,
        hook: HookName,
        tenant_id: str,
        payload: dict[str, Any],
        fail_closed: bool = True,
    ) -> dict[str, Any]:
        report = self._runtime.execute_hook(
            hook=hook,
            tenant_id=tenant_id,
            payload=payload,
            fail_closed=fail_closed,
        )
        return dict(report.payload)


@dataclass
class InMemoryEmailOTPDelivery:
    sent_messages: list[dict[str, str]] = field(default_factory=list)

    def send_code(self, *, email: str, code: str, tenant_id: str, subject_id: str) -> None:
        self.sent_messages.append(
            {"email": email, "code": code, "tenant_id": tenant_id, "subject_id": subject_id}
        )


@dataclass(frozen=True)
class JWKSCacheEntry:
    fetched_at: datetime
    keyset: jwk.KeySet


class WebAuthnHandler(Protocol):
    def begin_registration(
        self, *, session_id: str, user_name: str, rp_id: str, rp_name: str
    ) -> dict[str, object]: ...
    def finish_registration(
        self,
        *,
        state_id: str,
        credential_id: str,
        public_key: str,
        transports: tuple[str, ...],
        sign_count: int,
        credential_response: str | None = None,
        expected_origin: str | None = None,
        rp_id: str | None = None,
    ) -> dict[str, object]: ...
    def begin_authentication(self, *, session_id: str, challenge_id: str) -> dict[str, object]: ...
    def finish_authentication(
        self,
        *,
        session_id: str,
        state_id: str,
        credential_id: str,
        sign_count: int,
        authentication_response: str | None = None,
        expected_origin: str | None = None,
        rp_id: str | None = None,
    ) -> dict[str, object]: ...


class ServiceWebAuthnHandler:
    def __init__(
        self,
        *,
        session_store: SessionStore,
        challenge_store: MFAChallengeStore,
        credential_repository: WebAuthnCredentialRepository,
        registration_state_repository: WebAuthnRegistrationStateRepository,
        authentication_state_repository: WebAuthnAuthenticationStateRepository,
        verifier: WebAuthnVerifier | None = None,
    ) -> None:
        self._session_store = session_store
        self._challenge_store = challenge_store
        self._credential_repository = credential_repository
        self._registration_state_repository = registration_state_repository
        self._authentication_state_repository = authentication_state_repository
        self._verifier = verifier or build_default_webauthn_verifier()

    def begin_registration(
        self, *, session_id: str, user_name: str, rp_id: str, rp_name: str
    ) -> dict[str, object]:
        session = self._load_session(session_id)
        result = begin_registration(
            session=session,
            user_name=user_name,
            rp_id=rp_id,
            rp_name=rp_name,
            state_repository=self._registration_state_repository,
        )
        return {"state_id": result.state.state_id, "options": result.options}

    def finish_registration(
        self,
        *,
        state_id: str,
        credential_id: str,
        public_key: str,
        transports: tuple[str, ...],
        sign_count: int,
        credential_response: str | None = None,
        expected_origin: str | None = None,
        rp_id: str | None = None,
    ) -> dict[str, object]:
        credential = finish_registration(
            state_id=state_id,
            credential_id=credential_id,
            public_key=public_key,
            transports=transports,
            sign_count=sign_count,
            credential_repository=self._credential_repository,
            state_repository=self._registration_state_repository,
            verifier=self._verifier,
            credential_response=credential_response,
            expected_origin=expected_origin,
            rp_id=rp_id,
        )
        return {
            "credential_id": credential.credential_id,
            "subject_id": credential.subject_id,
            "tenant_id": credential.tenant_id,
        }

    def begin_authentication(self, *, session_id: str, challenge_id: str) -> dict[str, object]:
        session = self._load_session(session_id)
        result = begin_authentication_for_mfa(
            session=session,
            mfa_challenge_id=challenge_id,
            credential_repository=self._credential_repository,
            state_repository=self._authentication_state_repository,
        )
        return {"state_id": result.state.state_id, "options": result.options}

    def finish_authentication(
        self,
        *,
        session_id: str,
        state_id: str,
        credential_id: str,
        sign_count: int,
        authentication_response: str | None = None,
        expected_origin: str | None = None,
        rp_id: str | None = None,
    ) -> dict[str, object]:
        session = self._load_session(session_id)
        challenge = finish_authentication_for_mfa(
            state_id=state_id,
            session=session,
            credential_id=credential_id,
            new_sign_count=sign_count,
            credential_repository=self._credential_repository,
            state_repository=self._authentication_state_repository,
            challenge_store=self._challenge_store,
            verifier=self._verifier,
            authentication_response=authentication_response,
            expected_origin=expected_origin,
            rp_id=rp_id,
        )
        upgraded = upgrade_session_with_verified_challenge(
            challenge_id=challenge.challenge_id,
            challenge_store=self._challenge_store,
            session_store=self._session_store,
            methods={"webauthn"},
        )
        return {"sid": upgraded.session_id, "acr": upgraded.acr, "amr": list(upgraded.amr)}

    def _load_session(self, session_id: str) -> Session:
        session = self._session_store.get(session_id)
        if session is None or session.revoked or session.is_expired():
            raise ValueError("invalid_session")
        return session


_HTTP_OPENER = build_opener(HTTPHandler, HTTPSHandler)


def _http_url(value: str) -> str:
    scheme = urlparse(value).scheme.lower()
    if scheme not in {"http", "https"}:
        raise OIDCProtocolError("unsupported_oidc_url_scheme")
    return value


def _open_http_request(request: Request) -> Any:
    _http_url(request.full_url)
    return _HTTP_OPENER.open(request, timeout=10)


class HTTPOIDCMetadataClient:
    def fetch_metadata(self, *, discovery_url: str) -> dict[str, object]:
        request = Request(_http_url(discovery_url), method="GET")
        try:
            with _open_http_request(request) as response:
                return cast(dict[str, object], json.loads(response.read().decode("utf-8")))
        except (HTTPError, URLError, TimeoutError) as exc:
            raise OIDCProtocolError(f"metadata_fetch_failed:{exc}") from exc


class HTTPOIDCCodeExchangeClient:
    def __init__(self) -> None:
        self._jwks_cache: dict[str, JWKSCacheEntry | jwk.KeySet] = {}
        self._jwks_cache_ttl_seconds = 300

    def exchange_code(
        self,
        *,
        provider: OIDCProviderConfig,
        metadata: OIDCProviderMetadata,
        code: str,
        redirect_uri: str,
        code_verifier: str,
    ) -> OIDCTokenResponse:
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": provider.client_id,
            "code_verifier": code_verifier,
        }
        if provider.client_secret is not None:
            payload["client_secret"] = provider.client_secret
        request = Request(
            _http_url(metadata.token_endpoint),
            data=urlencode(payload).encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with _open_http_request(request) as response:
                raw = json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError) as exc:
            raise OIDCProtocolError(f"token_exchange_failed:{exc}") from exc
        access_token = raw.get("access_token")
        token_type = raw.get("token_type")
        if not isinstance(access_token, str) or not isinstance(token_type, str):
            raise OIDCProtocolError("invalid_token_response")
        expires_in = raw.get("expires_in")
        return OIDCTokenResponse(
            access_token=access_token,
            token_type=token_type,
            expires_in=int(expires_in) if isinstance(expires_in, (int, float)) else None,
            id_token=str(raw["id_token"]) if raw.get("id_token") is not None else None,
            refresh_token=str(raw["refresh_token"])
            if raw.get("refresh_token") is not None
            else None,
            scope=str(raw["scope"]) if raw.get("scope") is not None else None,
        )

    def fetch_userinfo(
        self,
        *,
        provider: OIDCProviderConfig,
        metadata: OIDCProviderMetadata,
        token_response: OIDCTokenResponse,
    ) -> OIDCUserInfo:
        if metadata.userinfo_endpoint is None:
            raise OIDCProtocolError("userinfo_not_configured")
        request = Request(
            _http_url(metadata.userinfo_endpoint),
            headers={"Authorization": f"Bearer {token_response.access_token}"},
            method="GET",
        )
        try:
            with _open_http_request(request) as response:
                raw = json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError) as exc:
            raise OIDCProtocolError(f"userinfo_fetch_failed:{exc}") from exc
        subject = raw.get("sub")
        if not isinstance(subject, str):
            raise OIDCProtocolError("userinfo_missing_subject")
        return OIDCUserInfo(
            subject=subject,
            email=str(raw["email"]) if raw.get("email") is not None else None,
            email_verified=bool(raw["email_verified"])
            if raw.get("email_verified") is not None
            else None,
            claims={str(key): value for key, value in raw.items()},
        )

    def validate_id_token(
        self,
        *,
        provider: OIDCProviderConfig,
        metadata: OIDCProviderMetadata,
        token_response: OIDCTokenResponse,
        expected_nonce: str,
    ) -> OIDCIDTokenClaims:
        if token_response.id_token is None:
            raise OIDCProtocolError("missing_id_token")
        if metadata.jwks_uri is None:
            raise OIDCProtocolError("jwks_not_configured")
        claims = self._decode_verified_jwt_claims(
            token_response.id_token, jwks_uri=metadata.jwks_uri
        )
        issuer = claims.get("iss")
        subject = claims.get("sub")
        audience_raw = claims.get("aud")
        nonce = claims.get("nonce")
        if not isinstance(issuer, str) or not isinstance(subject, str):
            raise OIDCProtocolError("invalid_id_token_claims")
        if issuer.rstrip("/") != metadata.issuer.rstrip("/"):
            raise OIDCProtocolError("id_token_issuer_mismatch")
        audience = _audience_tuple(audience_raw)
        if provider.client_id not in audience:
            raise OIDCProtocolError("id_token_audience_mismatch")
        if nonce != expected_nonce:
            raise OIDCProtocolError("nonce_mismatch")
        now = int(datetime.now(tz=UTC).timestamp())
        exp = claims.get("exp")
        if isinstance(exp, int) and now > exp:
            raise OIDCProtocolError("id_token_expired")
        iat = claims.get("iat")
        if isinstance(iat, int) and iat > now + 60:
            raise OIDCProtocolError("id_token_issued_in_future")
        return OIDCIDTokenClaims(
            issuer=issuer,
            subject=subject,
            audience=audience,
            nonce=nonce if isinstance(nonce, str) else None,
        )

    def _decode_verified_jwt_claims(self, token: str, *, jwks_uri: str) -> dict[str, object]:
        keyset = self._get_cached_keyset(jwks_uri)
        try:
            decoded = jwt.decode(token, keyset)
        except Exception:
            refreshed_keyset = self._fetch_keyset(jwks_uri)
            self._jwks_cache[jwks_uri] = JWKSCacheEntry(
                fetched_at=datetime.now(tz=UTC),
                keyset=refreshed_keyset,
            )
            try:
                decoded = jwt.decode(token, refreshed_keyset)
            except Exception as retry_exc:
                raise OIDCProtocolError("invalid_id_token_signature") from retry_exc
        claims = decoded.claims
        if not isinstance(claims, dict):
            raise OIDCProtocolError("invalid_id_token_claims")
        return {str(key): value for key, value in claims.items()}

    def _get_cached_keyset(self, jwks_uri: str) -> jwk.KeySet:
        entry = self._jwks_cache.get(jwks_uri)
        now = datetime.now(tz=UTC)
        if isinstance(entry, jwk.KeySet):
            entry = JWKSCacheEntry(fetched_at=now, keyset=entry)
            self._jwks_cache[jwks_uri] = entry
        if (
            entry is None
            or (now - entry.fetched_at).total_seconds() >= self._jwks_cache_ttl_seconds
        ):
            keyset = self._fetch_keyset(jwks_uri)
            entry = JWKSCacheEntry(fetched_at=now, keyset=keyset)
            self._jwks_cache[jwks_uri] = entry
        return entry.keyset

    def _fetch_keyset(self, jwks_uri: str) -> jwk.KeySet:
        request = Request(_http_url(jwks_uri), method="GET")
        try:
            with _open_http_request(request) as response:
                raw = json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError) as exc:
            raise OIDCProtocolError(f"jwks_fetch_failed:{exc}") from exc
        keys = raw.get("keys")
        if not isinstance(keys, list):
            raise OIDCProtocolError("invalid_jwks_document")
        return jwk.KeySet.import_key_set(jwk.KeySetSerialization(keys=keys))


class ServiceOIDCHandler:
    def __init__(
        self,
        *,
        providers: dict[str, OIDCProviderConfig],
        metadata_client: OIDCMetadataClient,
        exchange_client: OIDCCodeExchangeClient,
        link_repository: IdentityLinkRepository,
        group_role_mapping_repository: InMemoryGroupRoleMappingRepository
        | SQLGroupRoleMappingRepository,
        claim_attribute_mapping_repository: InMemoryClaimAttributeMappingRepository
        | SQLClaimAttributeMappingRepository,
        login_state_repository: OIDCLoginStateRepository,
        audit_repository: FederationAuditRepository,
        clients: InMemoryClientRegistry,
        subjects: InMemorySubjectDirectory,
        assignments: InMemoryAssignmentStore,
        authorization_engine: AuthorizationEngine,
        scope_policy: DefaultScopePolicy,
        session_store: SessionStore,
        token_manager: TokenKeyManager,
        access_token_audience: str,
        session_ttl_seconds: int,
        observability: ServiceObservabilityRecorder,
    ) -> None:
        self._providers = dict(providers)
        self._metadata_client = metadata_client
        self._exchange_client = exchange_client
        self._link_repository = link_repository
        self._group_role_mapping_repository = group_role_mapping_repository
        self._claim_attribute_mapping_repository = claim_attribute_mapping_repository
        self._login_state_repository = login_state_repository
        self._audit_repository = audit_repository
        self._clients = clients
        self._subjects = subjects
        self._assignments = assignments
        self._authorization_engine = authorization_engine
        self._scope_policy = scope_policy
        self._session_store = session_store
        self._token_manager = token_manager
        self._access_token_audience = access_token_audience
        self._session_ttl_seconds = session_ttl_seconds
        self._metadata_cache: dict[str, OIDCProviderMetadata] = {}
        self._observability = observability

    def add_provider(self, provider: OIDCProviderConfig) -> None:
        self._providers[provider.provider_id] = provider
        self._metadata_cache.pop(provider.provider_id, None)

    def begin_login(
        self, *, provider_id: str, tenant_id: str, redirect_uri: str
    ) -> dict[str, object]:
        provider = self._provider(provider_id)
        metadata = self._metadata(provider)
        state, request = begin_oidc_login(
            provider=provider,
            metadata=metadata,
            tenant_id=tenant_id,
            redirect_uri=redirect_uri,
            state_repository=self._login_state_repository,
            audit_repository=self._audit_repository,
        )
        return {
            "provider_id": provider.provider_id,
            "tenant_id": tenant_id,
            "state_id": state.state_id,
            "authorization_url": build_authorization_url(request),
            "authorization_request": request.__dict__,
        }

    def complete_callback(
        self,
        *,
        provider_id: str,
        tenant_id: str,
        client_id: str,
        redirect_uri: str,
        code: str,
        state: str,
        scope: str | None = None,
    ) -> dict[str, object]:
        provider = self._provider(provider_id)
        metadata = self._metadata(provider)
        profile = complete_oidc_callback(
            provider=provider,
            metadata=metadata,
            tenant_id=tenant_id,
            callback=OIDCCallbackPayload(code=code, state=state, redirect_uri=redirect_uri),
            state_repository=self._login_state_repository,
            exchange_client=self._exchange_client,
            audit_repository=self._audit_repository,
        )
        subject_id = self._subject_id_for_profile(profile)
        federation = federate_oidc_profile(
            subject_id=subject_id,
            profile=profile,
            link_repository=self._link_repository,
            group_role_mapping_repository=self._group_role_mapping_repository,
            claim_attribute_mapping_repository=self._claim_attribute_mapping_repository,
        )
        self._sync_subject(federation=federation, profile=profile)
        existing_assignment = self._assignments.get_assignments(
            federation.subject_id,
            federation.tenant_id,
        )
        merged_roles = set(federation.resolved_roles)
        if existing_assignment is not None:
            merged_roles.update(existing_assignment.roles)
        self._assignments.assign(
            TenantRoleAssignment(
                subject_id=federation.subject_id,
                tenant_id=federation.tenant_id,
                roles=merged_roles,
            )
        )
        requested_scopes = set(scope.split()) if scope else {"openid"}
        try:
            token_response = self._issue_federated_tokens(
                subject_id=federation.subject_id,
                tenant_id=tenant_id,
                client_id=client_id,
                requested_scopes=requested_scopes,
                provider_id=provider_id,
                subject_attributes=federation.subject_attributes,
            )
        except Exception as exc:
            self._observability.record_metric(name="federation.failures")
            self._observability.record_event(
                event_type="oidc.session.issued",
                status="failed",
                details={"provider_id": provider_id, "tenant_id": tenant_id, "reason": str(exc)},
                level="WARNING",
            )
            self._audit_repository.save(
                FederationAuditRecord.create(
                    event_type="oidc.session.issued",
                    provider_id=provider_id,
                    tenant_id=tenant_id,
                    status="failed",
                    client_id=client_id,
                    subject_id=federation.subject_id,
                    external_subject=federation.external_subject,
                    reason=str(exc),
                    details={"scopes_count": len(requested_scopes)},
                )
            )
            raise
        self._observability.record_event(
            event_type="oidc.session.issued",
            status="succeeded",
            details={"provider_id": provider_id, "tenant_id": tenant_id},
        )
        self._audit_repository.save(
            FederationAuditRecord.create(
                event_type="oidc.session.issued",
                provider_id=provider_id,
                tenant_id=tenant_id,
                status="succeeded",
                client_id=client_id,
                subject_id=federation.subject_id,
                external_subject=federation.external_subject,
                details={
                    "roles_count": len(federation.resolved_roles),
                    "attributes_count": len(federation.subject_attributes),
                    "scopes_count": len(requested_scopes),
                },
            )
        )
        return {
            **token_response.__dict__,
            "subject_id": federation.subject_id,
            "tenant_id": federation.tenant_id,
            "provider_id": federation.provider_id,
            "resolved_roles": list(federation.resolved_roles),
            "subject_attributes": federation.subject_attributes,
        }

    def list_audit_records(
        self, *, tenant_id: str, provider_id: str | None = None
    ) -> tuple[FederationAuditRecord, ...]:
        return tuple(
            self._audit_repository.list_for_tenant(tenant_id=tenant_id, provider_id=provider_id)
        )

    def add_group_role_mapping(self, mapping: GroupRoleMapping) -> None:
        self._group_role_mapping_repository.add(mapping)

    def add_claim_attribute_mapping(self, mapping: ClaimAttributeMapping) -> None:
        self._claim_attribute_mapping_repository.add(mapping)

    def _provider(self, provider_id: str) -> OIDCProviderConfig:
        provider = self._providers.get(provider_id)
        if provider is None:
            raise OIDCProtocolError("unknown_provider")
        return provider

    def _metadata(self, provider: OIDCProviderConfig) -> OIDCProviderMetadata:
        cached = self._metadata_cache.get(provider.provider_id)
        if cached is not None:
            return cached
        metadata = discover_provider_metadata(
            provider=provider, metadata_client=self._metadata_client
        )
        self._metadata_cache[provider.provider_id] = metadata
        return metadata

    def _subject_id_for_profile(self, profile: OIDCExternalProfile) -> str:
        existing = self._link_repository.get(
            provider_id=profile.provider_id,
            external_subject=profile.external_subject,
            tenant_id=profile.tenant_id,
        )
        if existing is not None:
            return existing.subject_id
        return f"idp:{profile.tenant_id}:{profile.provider_id}:{profile.external_subject}"

    def _sync_subject(
        self, *, federation: OIDCFederationResult, profile: OIDCExternalProfile
    ) -> None:
        existing = self._subjects.get_subject(federation.subject_id)
        tenants = set(existing.tenants) if existing is not None else set()
        tenants.add(federation.tenant_id)
        username = (
            profile.email
            or (existing.username if existing is not None else None)
            or federation.external_subject
        )
        email = profile.email or (existing.email if existing is not None else None)
        self._subjects.add(
            Subject(
                subject_id=federation.subject_id,
                tenants=tenants,
                username=username,
                email=email,
            )
        )

    def _issue_federated_tokens(
        self,
        *,
        subject_id: str,
        tenant_id: str,
        client_id: str,
        requested_scopes: set[str],
        provider_id: str,
        subject_attributes: dict[str, str | int | float | bool],
    ) -> TokenResponse:
        subject = self._subjects.get_subject(subject_id)
        if subject is None:
            raise OIDCProtocolError("unknown_subject")
        client = self._clients.get_client(client_id)
        if client is None:
            raise OIDCProtocolError("unknown_client")
        client.validate_tenant(tenant_id)
        client.validate_scopes(requested_scopes)
        session, refresh_token = issue_session_and_refresh_token(
            subject_id=subject_id,
            client_id=client_id,
            tenant_id=tenant_id,
            requested_scopes=requested_scopes,
            session_store=self._session_store,
            token_manager=self._token_manager,
            session_ttl_seconds=self._session_ttl_seconds,
            initial_amr={"federated", "oidc"},
        )
        roles = self._authorization_engine.resolve_roles(subject_id=subject_id, tenant_id=tenant_id)
        permissions = self._authorization_engine.resolve_permissions(
            subject_id=subject_id, tenant_id=tenant_id
        )
        filtered_scopes = self._scope_policy.filter_scopes(
            requested_scopes=requested_scopes,
            permissions=permissions,
        )
        if filtered_scopes != requested_scopes:
            raise OIDCProtocolError("requested_scope_not_permitted")
        access_token = self._token_manager.issue_jwt(
            subject=subject_id,
            audience=self._access_token_audience,
            extra_claims={
                "scp": list(filtered_scopes),
                "cid": client.client_id,
                "tid": tenant_id,
                "roles": list(roles),
                "sid": session.session_id,
                "ver": session.version,
                "acr": session.acr,
                "amr": list(session.amr),
                "idp": provider_id,
                "subject_attributes": subject_attributes,
            },
        )
        id_claims = build_id_token_claims(
            ctx=self._token_request_context(client=client, subject=subject, scopes=filtered_scopes),
            issuer=self._token_manager._config.issuer,
            ttl_seconds=self._token_manager._config.access_token_ttl_seconds,
        )
        id_token = self._token_manager.issue_jwt(
            subject=subject_id,
            audience=client.client_id,
            extra_claims={
                **id_claims,
                "tid": tenant_id,
                "acr": session.acr,
                "amr": list(session.amr),
                "idp": provider_id,
                "subject_attributes": subject_attributes,
            },
        )
        return TokenResponse(
            access_token=access_token,
            id_token=id_token,
            refresh_token=refresh_token,
        )

    def _token_request_context(
        self,
        *,
        client: OAuthClient,
        subject: Subject,
        scopes: set[str],
    ) -> TokenRequestContext:
        from astraauth.core.oauth.models import TokenRequestContext

        return TokenRequestContext(
            client=client,
            subject=subject,
            scopes=scopes,
            nonce=None,
            auth_time=datetime.now(tz=UTC),
        )


class ServiceObservabilityRecorder:
    def __init__(self, config: AuthConfig, *, home: Path | None = None) -> None:
        self._config = config
        self._home = home
        self.correlation_header_name = config.observability.correlation_header_name

    def next_correlation_id(self, *, supplied: str | None = None) -> str:
        return next_correlation_id(supplied=supplied)

    def record_metric(self, *, name: str, value: int = 1) -> None:
        record_metric(config=self._config, name=name, value=value, home=self._home)

    def record_event(
        self,
        *,
        event_type: str,
        status: str,
        correlation_id: str | None = None,
        details: dict[str, Any] | None = None,
        level: str = "INFO",
    ) -> None:
        record_event(
            config=self._config,
            event_type=event_type,
            status=status,
            correlation_id=correlation_id,
            details=details,
            level=level,
            home=self._home,
        )


@dataclass
class AstraAuthService:
    adapter: OAuthHTTPAdapter
    clients: InMemoryClientRegistry
    subjects: InMemorySubjectDirectory
    codes: InMemoryAuthorizationCodeStore
    sessions: SessionStore
    roles: InMemoryRoleStore
    assignments: InMemoryAssignmentStore
    password_authenticator: InMemoryPasswordAuthenticator
    api_key_authenticator: InMemoryAPIKeyAuthenticator
    token_manager: TokenKeyManager
    plugin_runtime: PluginRuntime
    hook_runner: ServiceHookRunner
    mfa_challenges: MFAChallengeStore
    totp_factors: TOTPFactorStore
    email_otp_factors: EmailOTPFactorStore
    email_otp_codes: EmailOTPCodeStore
    email_delivery: InMemoryEmailOTPDelivery
    webauthn_handler: ServiceWebAuthnHandler
    oidc_handler: ServiceOIDCHandler
    identity_links: IdentityLinkRepository
    oidc_group_role_mappings: InMemoryGroupRoleMappingRepository | SQLGroupRoleMappingRepository
    oidc_claim_attribute_mappings: (
        InMemoryClaimAttributeMappingRepository | SQLClaimAttributeMappingRepository
    )
    oidc_login_states: OIDCLoginStateRepository
    oidc_audit: FederationAuditRepository
    throttle_store: ThrottleStore
    webauthn_credentials: WebAuthnCredentialRepository
    webauthn_registration_states: WebAuthnRegistrationStateRepository
    webauthn_authentication_states: WebAuthnAuthenticationStateRepository

    def add_client(self, client: OAuthClient) -> None:
        self.clients.add(client)

    def add_role(self, role: Role) -> None:
        self.roles.add_role(role)

    def assign_roles(self, *, subject_id: str, tenant_id: str, roles: set[str]) -> None:
        self.assignments.assign(
            TenantRoleAssignment(subject_id=subject_id, tenant_id=tenant_id, roles=roles)
        )

    def add_subject_password(
        self,
        *,
        subject: Subject,
        tenant_id: str,
        username: str,
        password: str,
    ) -> None:
        self.subjects.add(subject)
        self.password_authenticator.add(
            tenant_id=tenant_id,
            record=PasswordRecord(
                username=username,
                password_hash=hash_password(password),
                subject=subject,
            ),
        )

    def add_subject_password_hash(
        self,
        *,
        subject: Subject,
        tenant_id: str,
        username: str,
        password_hash: str,
    ) -> None:
        self.subjects.add(subject)
        self.password_authenticator.add(
            tenant_id=tenant_id,
            record=PasswordRecord(
                username=username,
                password_hash=password_hash,
                subject=subject,
            ),
        )

    def add_subject_api_key(
        self,
        *,
        subject: Subject,
        tenant_id: str,
        label: str,
        api_key_plaintext: str,
    ) -> None:
        self.subjects.add(subject)
        digest = digest_api_key(api_key_plaintext)
        self.api_key_authenticator.add(
            tenant_id=tenant_id,
            label=label,
            record=APIKeyRecord(key_digest=digest, subject=subject),
        )

    def enroll_subject_totp(
        self,
        *,
        subject_id: str,
        tenant_id: str,
        account_name: str,
        issuer: str = "AstraAuth",
    ) -> tuple[str, str]:
        enrollment = enroll_totp_factor(
            subject_id=subject_id,
            tenant_id=tenant_id,
            issuer=issuer,
            account_name=account_name,
            factor_store=self.totp_factors,
            provider=OTPAuthTOTPProvider(),
        )
        return enrollment.factor.factor_id, enrollment.provisioning_uri

    def activate_subject_totp(self, *, factor_id: str, code: str) -> None:
        activate_totp_factor(
            factor_id=factor_id,
            code=code,
            factor_store=self.totp_factors,
            provider=OTPAuthTOTPProvider(),
        )

    def enroll_subject_email_otp(
        self,
        *,
        subject_id: str,
        tenant_id: str,
        email: str,
        issuer: str = "AstraAuth",
    ) -> str:
        enrollment = enroll_email_otp_factor(
            subject_id=subject_id,
            tenant_id=tenant_id,
            email=email,
            issuer=issuer,
            factor_store=self.email_otp_factors,
        )
        return enrollment.factor.factor_id

    def activate_subject_email_otp(self, *, factor_id: str) -> None:
        activate_email_otp_factor(factor_id=factor_id, factor_store=self.email_otp_factors)

    def register_oidc_provider(self, *, provider: OIDCProviderConfig) -> None:
        self.oidc_handler.add_provider(provider)

    def add_oidc_group_role_mapping(self, mapping: GroupRoleMapping) -> None:
        self.oidc_handler.add_group_role_mapping(mapping)

    def add_oidc_claim_attribute_mapping(self, mapping: ClaimAttributeMapping) -> None:
        self.oidc_handler.add_claim_attribute_mapping(mapping)

    def list_oidc_audit_records(
        self,
        *,
        tenant_id: str,
        provider_id: str | None = None,
    ) -> tuple[FederationAuditRecord, ...]:
        return self.oidc_handler.list_audit_records(tenant_id=tenant_id, provider_id=provider_id)

    def register_plugin(self, plugin: Plugin, *, manifest: PluginManifest | None = None) -> None:
        self.plugin_runtime.register(plugin, manifest=manifest)

    def enable_plugin(self, *, tenant_id: str, plugin_name: str) -> None:
        self.plugin_runtime.enable_for_tenant(tenant_id=tenant_id, plugin_name=plugin_name)


def _build_session_store(config: AuthConfig) -> SessionStore:
    backend = config.persistence.database_for("sessions")
    if _uses_inmemory_backend(backend):
        return InMemorySessionStore()
    return SQLSessionStore(config.persistence.dsn_for("sessions", mode="sync"))


def _build_mfa_stores(
    config: AuthConfig,
) -> tuple[MFAChallengeStore, TOTPFactorStore, EmailOTPFactorStore, EmailOTPCodeStore]:
    backend = config.persistence.database_for("mfa")
    if _uses_inmemory_backend(backend):
        return (
            InMemoryMFAChallengeStore(),
            InMemoryTOTPFactorStore(),
            InMemoryEmailOTPFactorStore(),
            InMemoryEmailOTPCodeStore(),
        )
    dsn = config.persistence.dsn_for("mfa", mode="sync")
    return (
        SQLMFAChallengeStore(dsn),
        SQLTOTPFactorStore(dsn),
        SQLEmailOTPFactorStore(dsn),
        SQLEmailOTPCodeStore(dsn),
    )


def _build_webauthn_repositories(
    config: AuthConfig,
) -> tuple[
    WebAuthnCredentialRepository,
    WebAuthnRegistrationStateRepository,
    WebAuthnAuthenticationStateRepository,
]:
    backend = config.persistence.database_for("mfa")
    if _uses_inmemory_backend(backend):
        return (
            InMemoryWebAuthnCredentialRepository(),
            InMemoryWebAuthnRegistrationStateRepository(),
            InMemoryWebAuthnAuthenticationStateRepository(),
        )
    dsn = config.persistence.dsn_for("mfa", mode="sync")
    return (
        SQLWebAuthnCredentialRepository(dsn),
        SQLWebAuthnRegistrationStateRepository(dsn),
        SQLWebAuthnAuthenticationStateRepository(dsn),
    )


def _build_plugin_registry_store(config: AuthConfig) -> TenantPluginRegistryStore:
    backend = config.persistence.database_for("plugins")
    if _uses_inmemory_backend(backend):
        return InMemoryTenantPluginRegistryStore()
    return SQLTenantPluginRegistryStore(config.persistence.dsn_for("plugins", mode="sync"))


def _build_throttle_store(config: AuthConfig) -> ThrottleStore:
    backend = config.persistence.database_for("sessions")
    if _uses_inmemory_backend(backend):
        return InMemoryThrottleStore()
    return SharedThrottleStore(
        config.persistence.dsn_for("sessions", mode="sync"),
        table_name="astraauth_throttle_state",
    )


def _plugin_audit_log_path(*, home: Path | None = None) -> Path | None:
    if home is None:
        return None
    return home / "logs" / "plugin-runtime-audit.jsonl"


def _build_plugin_audit_callback(
    *,
    home: Path | None = None,
) -> Callable[[PluginAuditRecord], None] | None:
    path = _plugin_audit_log_path(home=home)
    if path is None:
        return None

    def _record(record: PluginAuditRecord) -> None:
        ensure_private_directory(path.parent)
        payload = {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "tenant_id": record.tenant_id,
            "plugin_name": record.plugin_name,
            "target": record.target,
            "execution_type": record.execution_type,
            "status": record.status,
            "fail_closed": record.fail_closed,
            "duration_ms": record.duration_ms,
            "error_classification": record.error_classification,
            "message": record.message,
        }
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True))
            handle.write("\n")
        enforce_private_file_permissions(path)

    return _record


def _build_oidc_provider_map(config: AuthConfig) -> dict[str, OIDCProviderConfig]:
    providers: dict[str, OIDCProviderConfig] = {}
    for provider in config.idp.oidc_providers:
        providers[provider.provider_id] = _oidc_provider_from_settings(provider)
    return providers


def _oidc_provider_from_settings(settings: OIDCProviderSettings) -> OIDCProviderConfig:
    return OIDCProviderConfig(
        provider_id=settings.provider_id,
        issuer=settings.issuer,
        client_id=settings.client_id,
        client_secret=settings.client_secret,
        discovery_url=settings.discovery_url,
        authorization_endpoint=settings.authorization_endpoint,
        token_endpoint=settings.token_endpoint,
        userinfo_endpoint=settings.userinfo_endpoint,
        jwks_uri=settings.jwks_uri,
        scopes=settings.scopes,
    )


def _audience_tuple(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(str(item) for item in value)
    if isinstance(value, tuple):
        return tuple(str(item) for item in value)
    raise OIDCProtocolError("invalid_id_token_audience")


def _build_idp_repositories(
    config: AuthConfig,
) -> tuple[
    IdentityLinkRepository,
    InMemoryGroupRoleMappingRepository | SQLGroupRoleMappingRepository,
    InMemoryClaimAttributeMappingRepository | SQLClaimAttributeMappingRepository,
    OIDCLoginStateRepository,
    FederationAuditRepository,
]:
    backend = config.persistence.database_for("idp")
    if _uses_inmemory_backend(backend):
        return (
            InMemoryIdentityLinkRepository(),
            InMemoryGroupRoleMappingRepository(),
            InMemoryClaimAttributeMappingRepository(),
            InMemoryOIDCLoginStateRepository(),
            InMemoryFederationAuditRepository(),
        )
    dsn = config.persistence.dsn_for("idp", mode="sync")
    return (
        SQLIdentityLinkRepository(dsn),
        SQLGroupRoleMappingRepository(dsn),
        SQLClaimAttributeMappingRepository(dsn),
        SQLOIDCLoginStateRepository(dsn),
        SQLFederationAuditRepository(dsn),
    )


def _uses_inmemory_backend(backend: RelationalStoreConfig) -> bool:
    return backend.backend == "sqlite" and backend.database == ":memory:" and backend.dsn is None


def build_service(
    *,
    config: AuthConfig | None = None,
    token_manager: TokenKeyManager | None = None,
    observability_home: Path | None = None,
    access_token_audience: str = "api",
    code_ttl_seconds: int = 300,
    session_ttl_seconds: int = 3600,
    permission_scope_map: dict[str, str] | None = None,
    default_plugins_enabled: bool = True,
    plugin_registry_store: TenantPluginRegistryStore | None = None,
    plugin_trust_policy: PluginTrustPolicy | None = None,
    webauthn_verifier: WebAuthnVerifier | None = None,
) -> AstraAuthService:
    cfg = config or AuthConfig()
    cfg.validate_settings()
    runtime_token_manager = token_manager or TokenKeyManager(cfg)

    clients = InMemoryClientRegistry()
    subjects = InMemorySubjectDirectory()
    codes = InMemoryAuthorizationCodeStore()
    sessions = _build_session_store(cfg)
    roles = InMemoryRoleStore()
    assignments = InMemoryAssignmentStore()
    authz = AuthorizationEngine(role_store=roles, assignment_store=assignments)

    scope_map = permission_scope_map or {"openid": "openid"}
    scope_policy = DefaultScopePolicy(scope_map, strict_mode=True)

    password_authenticator = InMemoryPasswordAuthenticator(MultiSchemePasswordVerifier())
    api_key_authenticator = InMemoryAPIKeyAuthenticator(Sha256APIKeyHasher())
    plugin_store = plugin_registry_store or _build_plugin_registry_store(cfg)
    throttle_store = _build_throttle_store(cfg)
    plugin_runtime = PluginRuntime(
        allowed_column_tables={"plugin_risk_extension"},
        registry_store=plugin_store,
        trust_policy=plugin_trust_policy,
        audit_callback=_build_plugin_audit_callback(home=observability_home),
    )
    hook_runner = ServiceHookRunner(plugin_runtime)
    observability = ServiceObservabilityRecorder(cfg, home=observability_home)
    event_bus = InMemoryEventBus()
    mfa_challenges, totp_factors, email_otp_factors, email_otp_codes = _build_mfa_stores(cfg)
    webauthn_credentials, webauthn_registration_states, webauthn_authentication_states = (
        _build_webauthn_repositories(cfg)
    )
    oidc_providers = _build_oidc_provider_map(cfg)
    (
        identity_links,
        oidc_group_role_mappings,
        oidc_claim_attribute_mappings,
        oidc_login_states,
        oidc_audit,
    ) = _build_idp_repositories(cfg)
    webauthn_handler = ServiceWebAuthnHandler(
        session_store=sessions,
        challenge_store=mfa_challenges,
        credential_repository=webauthn_credentials,
        registration_state_repository=webauthn_registration_states,
        authentication_state_repository=webauthn_authentication_states,
        verifier=webauthn_verifier,
    )
    oidc_handler = ServiceOIDCHandler(
        providers=oidc_providers,
        metadata_client=HTTPOIDCMetadataClient(),
        exchange_client=HTTPOIDCCodeExchangeClient(),
        link_repository=identity_links,
        group_role_mapping_repository=oidc_group_role_mappings,
        claim_attribute_mapping_repository=oidc_claim_attribute_mappings,
        login_state_repository=oidc_login_states,
        audit_repository=oidc_audit,
        clients=clients,
        subjects=subjects,
        assignments=assignments,
        authorization_engine=authz,
        scope_policy=scope_policy,
        session_store=sessions,
        token_manager=runtime_token_manager,
        access_token_audience=access_token_audience,
        session_ttl_seconds=session_ttl_seconds,
        observability=observability,
    )
    email_delivery = InMemoryEmailOTPDelivery()

    if default_plugins_enabled:
        plugin_runtime.register(GeoSignalPlugin())
        plugin_runtime.register(RiskSignalPlugin())
        plugin_runtime.enable_for_tenant(tenant_id="Default", plugin_name="geo")
        plugin_runtime.enable_for_tenant(tenant_id="Default", plugin_name="risk")

    adapter = OAuthHTTPAdapter(
        clients=clients,
        subjects=subjects,
        codes=codes,
        session_store=sessions,
        token_manager=runtime_token_manager,
        access_token_audience=access_token_audience,
        code_ttl_seconds=code_ttl_seconds,
        session_ttl_seconds=session_ttl_seconds,
        authorization_engine=authz,
        scope_policy=scope_policy,
        password_authenticator=password_authenticator,
        api_key_authenticator=api_key_authenticator,
        hook_runner=hook_runner,
        mfa_challenge_store=mfa_challenges,
        totp_factor_store=totp_factors,
        totp_provider=OTPAuthTOTPProvider(),
        email_otp_factor_store=email_otp_factors,
        email_otp_code_store=email_otp_codes,
        email_otp_delivery=email_delivery,
        webauthn_handler=webauthn_handler,
        oidc_handler=oidc_handler,
        event_bus=event_bus,
        observability=observability,
        throttle_store=throttle_store,
    )

    return AstraAuthService(
        adapter=adapter,
        clients=clients,
        subjects=subjects,
        codes=codes,
        sessions=sessions,
        roles=roles,
        assignments=assignments,
        password_authenticator=password_authenticator,
        api_key_authenticator=api_key_authenticator,
        token_manager=runtime_token_manager,
        plugin_runtime=plugin_runtime,
        hook_runner=hook_runner,
        mfa_challenges=mfa_challenges,
        totp_factors=totp_factors,
        email_otp_factors=email_otp_factors,
        email_otp_codes=email_otp_codes,
        email_delivery=email_delivery,
        webauthn_handler=webauthn_handler,
        oidc_handler=oidc_handler,
        identity_links=identity_links,
        oidc_group_role_mappings=oidc_group_role_mappings,
        oidc_claim_attribute_mappings=oidc_claim_attribute_mappings,
        oidc_login_states=oidc_login_states,
        oidc_audit=oidc_audit,
        throttle_store=throttle_store,
        webauthn_credentials=webauthn_credentials,
        webauthn_registration_states=webauthn_registration_states,
        webauthn_authentication_states=webauthn_authentication_states,
    )


def build_inmemory_service(
    *,
    config: AuthConfig | None = None,
    access_token_audience: str = "api",
    code_ttl_seconds: int = 300,
    session_ttl_seconds: int = 3600,
    permission_scope_map: dict[str, str] | None = None,
    default_plugins_enabled: bool = True,
    plugin_registry_store: TenantPluginRegistryStore | None = None,
    webauthn_verifier: WebAuthnVerifier | None = None,
) -> AstraAuthService:
    cfg = config or AuthConfig()
    return build_service(
        config=cfg,
        access_token_audience=access_token_audience,
        code_ttl_seconds=code_ttl_seconds,
        session_ttl_seconds=session_ttl_seconds,
        permission_scope_map=permission_scope_map,
        default_plugins_enabled=default_plugins_enabled,
        plugin_registry_store=plugin_registry_store,
        webauthn_verifier=webauthn_verifier,
    )
