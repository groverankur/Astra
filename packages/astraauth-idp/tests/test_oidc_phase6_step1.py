from __future__ import annotations

from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse

from astraauth_idp import (
    ClaimAttributeMapping,
    FederationMappingError,
    GroupRoleMapping,
    InMemoryClaimAttributeMappingRepository,
    InMemoryFederationAuditRepository,
    InMemoryGroupRoleMappingRepository,
    InMemoryIdentityLinkRepository,
    InMemoryOIDCLoginStateRepository,
    OIDCCallbackPayload,
    OIDCExternalProfile,
    OIDCIDTokenClaims,
    OIDCLoginState,
    OIDCProtocolError,
    OIDCProviderConfig,
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
    link_or_update_external_identity,
)


class _MetadataClient:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload
        self.requested_url: str | None = None

    def fetch_metadata(self, *, discovery_url: str) -> dict[str, object]:
        self.requested_url = discovery_url
        return self.payload


class _ExchangeClient:
    def __init__(self) -> None:
        self.last_code_verifier: str | None = None
        self.nonce = "nonce-1"
        self.subject = "ext-user-2"

    def exchange_code(
        self,
        *,
        provider: OIDCProviderConfig,
        metadata: object,
        code: str,
        redirect_uri: str,
        code_verifier: str,
    ) -> OIDCTokenResponse:
        self.last_code_verifier = code_verifier
        assert provider.provider_id == "oidc-corp"
        assert code == "auth-code-1"
        assert redirect_uri == "https://app.example.com/callback"
        return OIDCTokenResponse(access_token="access-1", token_type="Bearer", id_token="id-1")

    def validate_id_token(
        self,
        *,
        provider: OIDCProviderConfig,
        metadata: object,
        token_response: OIDCTokenResponse,
        expected_nonce: str,
    ) -> OIDCIDTokenClaims:
        assert provider.provider_id == "oidc-corp"
        assert token_response.id_token == "id-1"
        return OIDCIDTokenClaims(
            issuer="https://issuer.example.com",
            subject=self.subject,
            audience=("client-1",),
            nonce=expected_nonce if self.nonce == "nonce-1" else self.nonce,
        )

    def fetch_userinfo(
        self,
        *,
        provider: OIDCProviderConfig,
        metadata: object,
        token_response: OIDCTokenResponse,
    ) -> OIDCUserInfo:
        assert provider.provider_id == "oidc-corp"
        assert token_response.access_token == "access-1"
        return OIDCUserInfo(
            subject=self.subject,
            email="bob@example.com",
            email_verified=True,
            claims={"groups": ("admins",), "department": "Security"},
        )


def _profile() -> OIDCExternalProfile:
    return OIDCExternalProfile(
        provider_id="oidc-corp",
        external_subject="ext-user-1",
        tenant_id="tenant-1",
        email="alice@example.com",
        email_verified=True,
        claims={
            "groups": ("finance", "reviewers"),
            "department": "Finance",
            "employee_type": "FULL_TIME",
        },
    )


def _provider_config() -> OIDCProviderConfig:
    return OIDCProviderConfig(
        provider_id="oidc-corp",
        issuer="https://issuer.example.com",
        client_id="client-1",
        client_secret="secret-1",
    )


def _provider_state(*, created_at: datetime, expires_at: datetime) -> OIDCLoginState:
    return OIDCLoginState(
        state_id="state-1",
        provider_id="oidc-corp",
        tenant_id="tenant-1",
        redirect_uri="https://app.example.com/callback",
        code_verifier="verifier-1",
        nonce="nonce-1",
        created_at=created_at,
        expires_at=expires_at,
    )


def test_federate_oidc_profile_maps_roles_and_attributes() -> None:
    links = InMemoryIdentityLinkRepository()
    group_roles = InMemoryGroupRoleMappingRepository()
    claim_attrs = InMemoryClaimAttributeMappingRepository()

    group_roles.add(
        GroupRoleMapping(
            provider_id="oidc-corp",
            tenant_id="tenant-1",
            external_group="finance",
            role_name="finance_approver",
        )
    )
    claim_attrs.add(
        ClaimAttributeMapping(
            provider_id="oidc-corp",
            tenant_id="tenant-1",
            claim_name="department",
            attribute_name="department",
            transform="lower",
        )
    )
    claim_attrs.add(
        ClaimAttributeMapping(
            provider_id="oidc-corp",
            tenant_id="tenant-1",
            claim_name="employee_type",
            attribute_name="employment_type",
            transform="lower",
        )
    )

    result = federate_oidc_profile(
        subject_id="user-1",
        profile=_profile(),
        link_repository=links,
        group_role_mapping_repository=group_roles,
        claim_attribute_mapping_repository=claim_attrs,
    )

    assert result.resolved_roles == ("finance_approver",)
    assert result.subject_attributes == {
        "department": "finance",
        "employment_type": "full_time",
    }
    assert result.link.subject_id == "user-1"


def test_linking_rejects_existing_external_identity_for_other_subject() -> None:
    links = InMemoryIdentityLinkRepository()
    link_or_update_external_identity(
        subject_id="user-1",
        profile=_profile(),
        link_repository=links,
    )

    try:
        link_or_update_external_identity(
            subject_id="user-2",
            profile=_profile(),
            link_repository=links,
        )
    except FederationMappingError as exc:
        assert "already_linked" in str(exc)
    else:
        raise AssertionError("expected identity linking conflict")


def test_required_claim_mapping_fails_when_claim_missing() -> None:
    claim_attrs = InMemoryClaimAttributeMappingRepository()
    claim_attrs.add(
        ClaimAttributeMapping(
            provider_id="oidc-corp",
            tenant_id="tenant-1",
            claim_name="cost_center",
            attribute_name="cost_center",
            required=True,
        )
    )

    try:
        federate_oidc_profile(
            subject_id="user-1",
            profile=_profile(),
            link_repository=InMemoryIdentityLinkRepository(),
            group_role_mapping_repository=InMemoryGroupRoleMappingRepository(),
            claim_attribute_mapping_repository=claim_attrs,
        )
    except FederationMappingError as exc:
        assert "missing_required_claim" in str(exc)
    else:
        raise AssertionError("expected required claim failure")


def test_sql_repositories_round_trip() -> None:
    dsn = ":memory:"
    links = SQLIdentityLinkRepository(dsn)
    group_roles = SQLGroupRoleMappingRepository(dsn)
    claim_attrs = SQLClaimAttributeMappingRepository(dsn)

    group_roles.add(
        GroupRoleMapping(
            provider_id="oidc-corp",
            tenant_id="tenant-1",
            external_group="finance",
            role_name="finance_approver",
        )
    )
    claim_attrs.add(
        ClaimAttributeMapping(
            provider_id="oidc-corp",
            tenant_id="tenant-1",
            claim_name="department",
            attribute_name="department",
            transform="lower",
        )
    )

    result = federate_oidc_profile(
        subject_id="user-1",
        profile=_profile(),
        link_repository=links,
        group_role_mapping_repository=group_roles,
        claim_attribute_mapping_repository=claim_attrs,
    )

    fetched = links.get(
        provider_id="oidc-corp",
        external_subject="ext-user-1",
        tenant_id="tenant-1",
    )
    assert fetched is not None
    assert fetched.subject_id == "user-1"
    assert result.resolved_roles == ("finance_approver",)


def test_discover_provider_metadata_builds_default_discovery_url() -> None:
    client = _MetadataClient(
        {
            "issuer": "https://issuer.example.com",
            "authorization_endpoint": "https://issuer.example.com/oauth2/authorize",
            "token_endpoint": "https://issuer.example.com/oauth2/token",
            "jwks_uri": "https://issuer.example.com/.well-known/jwks.json",
            "userinfo_endpoint": "https://issuer.example.com/oauth2/userinfo",
            "scopes_supported": ["openid", "profile", "email"],
        }
    )

    metadata = discover_provider_metadata(provider=_provider_config(), metadata_client=client)

    assert client.requested_url == "https://issuer.example.com/.well-known/openid-configuration"
    assert metadata.authorization_endpoint.endswith("/oauth2/authorize")
    assert metadata.scopes_supported == ("openid", "profile", "email")


def test_discover_provider_metadata_rejects_issuer_mismatch() -> None:
    client = _MetadataClient(
        {
            "issuer": "https://another-issuer.example.com",
            "authorization_endpoint": "https://issuer.example.com/oauth2/authorize",
            "token_endpoint": "https://issuer.example.com/oauth2/token",
            "jwks_uri": "https://issuer.example.com/.well-known/jwks.json",
        }
    )

    try:
        discover_provider_metadata(provider=_provider_config(), metadata_client=client)
    except OIDCProtocolError as exc:
        assert str(exc) == "issuer_mismatch"
    else:
        raise AssertionError("expected issuer mismatch")


def test_begin_oidc_login_persists_state_and_builds_pkce_request() -> None:
    repository = InMemoryOIDCLoginStateRepository()
    audit = InMemoryFederationAuditRepository()
    metadata_client = _MetadataClient(
        {
            "issuer": "https://issuer.example.com",
            "authorization_endpoint": "https://issuer.example.com/oauth2/authorize",
            "token_endpoint": "https://issuer.example.com/oauth2/token",
            "jwks_uri": "https://issuer.example.com/.well-known/jwks.json",
        }
    )
    metadata = discover_provider_metadata(provider=_provider_config(), metadata_client=metadata_client)

    state, request = begin_oidc_login(
        provider=_provider_config(),
        metadata=metadata,
        tenant_id="tenant-1",
        redirect_uri="https://app.example.com/callback",
        state_repository=repository,
        audit_repository=audit,
    )

    persisted = repository.get(state.state_id)
    assert persisted is not None
    assert persisted.code_verifier == state.code_verifier
    assert request.state == state.state_id
    assert request.nonce == state.nonce
    assert request.code_challenge
    parsed = urlparse(build_authorization_url(request))
    query = parse_qs(parsed.query)
    assert query["client_id"] == ["client-1"]
    assert query["state"] == [state.state_id]
    assert query["code_challenge_method"] == ["S256"]
    records = tuple(audit.list_for_tenant(tenant_id="tenant-1"))
    assert records[-1].status == "started"


def test_complete_oidc_callback_returns_external_profile() -> None:
    repository = InMemoryOIDCLoginStateRepository()
    audit = InMemoryFederationAuditRepository()
    metadata_client = _MetadataClient(
        {
            "issuer": "https://issuer.example.com",
            "authorization_endpoint": "https://issuer.example.com/oauth2/authorize",
            "token_endpoint": "https://issuer.example.com/oauth2/token",
            "jwks_uri": "https://issuer.example.com/.well-known/jwks.json",
            "userinfo_endpoint": "https://issuer.example.com/oauth2/userinfo",
        }
    )
    metadata = discover_provider_metadata(provider=_provider_config(), metadata_client=metadata_client)
    state, _ = begin_oidc_login(
        provider=_provider_config(),
        metadata=metadata,
        tenant_id="tenant-1",
        redirect_uri="https://app.example.com/callback",
        state_repository=repository,
        audit_repository=audit,
    )
    client = _ExchangeClient()

    profile = complete_oidc_callback(
        provider=_provider_config(),
        metadata=metadata,
        tenant_id="tenant-1",
        callback=OIDCCallbackPayload(
            code="auth-code-1",
            state=state.state_id,
            redirect_uri="https://app.example.com/callback",
        ),
        state_repository=repository,
        exchange_client=client,
        audit_repository=audit,
    )

    assert client.last_code_verifier == state.code_verifier
    assert profile.provider_id == "oidc-corp"
    assert profile.external_subject == "ext-user-2"
    assert profile.claims["department"] == "Security"
    assert repository.get(state.state_id) is None
    records = tuple(audit.list_for_tenant(tenant_id="tenant-1"))
    assert records[-1].status == "succeeded"
    assert records[-1].external_subject == "ext-user-2"


def test_complete_oidc_callback_rejects_expired_state() -> None:
    repository = SQLOIDCLoginStateRepository(":memory:")
    audit = SQLFederationAuditRepository(":memory:")
    expired = datetime.now(tz=UTC) - timedelta(minutes=10)
    repository.save(
        state=_provider_state(
            created_at=expired - timedelta(minutes=5),
            expires_at=expired,
        )
    )
    metadata_client = _MetadataClient(
        {
            "issuer": "https://issuer.example.com",
            "authorization_endpoint": "https://issuer.example.com/oauth2/authorize",
            "token_endpoint": "https://issuer.example.com/oauth2/token",
            "jwks_uri": "https://issuer.example.com/.well-known/jwks.json",
        }
    )
    metadata = discover_provider_metadata(provider=_provider_config(), metadata_client=metadata_client)

    try:
        complete_oidc_callback(
            provider=_provider_config(),
            metadata=metadata,
            tenant_id="tenant-1",
            callback=OIDCCallbackPayload(
                code="auth-code-1",
                state="state-1",
                redirect_uri="https://app.example.com/callback",
            ),
            state_repository=repository,
            exchange_client=_ExchangeClient(),
            audit_repository=audit,
        )
    except OIDCProtocolError as exc:
        assert str(exc) == "expired_state"
    else:
        raise AssertionError("expected expired state failure")
    records = tuple(audit.list_for_tenant(tenant_id="tenant-1"))
    assert records[-1].status == "failed"
    assert records[-1].reason == "expired_state"



def test_complete_oidc_callback_rejects_nonce_mismatch_and_consumes_state() -> None:
    repository = InMemoryOIDCLoginStateRepository()
    audit = InMemoryFederationAuditRepository()
    metadata_client = _MetadataClient(
        {
            "issuer": "https://issuer.example.com",
            "authorization_endpoint": "https://issuer.example.com/oauth2/authorize",
            "token_endpoint": "https://issuer.example.com/oauth2/token",
            "jwks_uri": "https://issuer.example.com/.well-known/jwks.json",
            "userinfo_endpoint": "https://issuer.example.com/oauth2/userinfo",
        }
    )
    metadata = discover_provider_metadata(provider=_provider_config(), metadata_client=metadata_client)
    state, _ = begin_oidc_login(
        provider=_provider_config(),
        metadata=metadata,
        tenant_id="tenant-1",
        redirect_uri="https://app.example.com/callback",
        state_repository=repository,
        audit_repository=audit,
    )
    client = _ExchangeClient()
    client.nonce = "wrong-nonce"

    try:
        complete_oidc_callback(
            provider=_provider_config(),
            metadata=metadata,
            tenant_id="tenant-1",
            callback=OIDCCallbackPayload(
                code="auth-code-1",
                state=state.state_id,
                redirect_uri="https://app.example.com/callback",
            ),
            state_repository=repository,
            exchange_client=client,
            audit_repository=audit,
        )
    except OIDCProtocolError as exc:
        assert str(exc) == "nonce_mismatch"
    else:
        raise AssertionError("expected nonce mismatch")

    assert repository.get(state.state_id) is None
    records = tuple(audit.list_for_tenant(tenant_id="tenant-1"))
    assert records[-1].status == "failed"
    assert records[-1].reason == "nonce_mismatch"
