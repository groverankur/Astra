from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Protocol

from astraauth.idp.models import (
    ClaimAttributeMapping,
    ExternalIdentityLink,
    FederationAuditRecord,
    GroupRoleMapping,
    OIDCLoginState,
)


class IdentityLinkRepository(Protocol):
    def save(self, link: ExternalIdentityLink) -> None: ...
    def get(
        self, *, provider_id: str, external_subject: str, tenant_id: str
    ) -> ExternalIdentityLink | None: ...
    def get_for_subject(
        self, *, subject_id: str, tenant_id: str
    ) -> Iterable[ExternalIdentityLink]: ...


class GroupRoleMappingRepository(Protocol):
    def add(self, mapping: GroupRoleMapping) -> None: ...
    def list_for_provider(
        self, *, provider_id: str, tenant_id: str
    ) -> Iterable[GroupRoleMapping]: ...


class ClaimAttributeMappingRepository(Protocol):
    def add(self, mapping: ClaimAttributeMapping) -> None: ...
    def list_for_provider(
        self, *, provider_id: str, tenant_id: str
    ) -> Iterable[ClaimAttributeMapping]: ...


class OIDCLoginStateRepository(Protocol):
    def save(self, state: OIDCLoginState) -> None: ...
    def get(self, state_id: str) -> OIDCLoginState | None: ...
    def delete(self, state_id: str) -> None: ...


class FederationAuditRepository(Protocol):
    def save(self, record: FederationAuditRecord) -> None: ...
    def list_for_tenant(
        self, *, tenant_id: str, provider_id: str | None = None
    ) -> Iterable[FederationAuditRecord]: ...


class BaseIdentityLinkRepository(IdentityLinkRepository, ABC):
    @abstractmethod
    def _iter_links(self) -> Iterable[ExternalIdentityLink]: ...

    def get_for_subject(self, *, subject_id: str, tenant_id: str) -> Iterable[ExternalIdentityLink]:
        return tuple(
            link
            for link in self._iter_links()
            if link.subject_id == subject_id and link.tenant_id == tenant_id
        )


class InMemoryIdentityLinkRepository(BaseIdentityLinkRepository):
    def __init__(self) -> None:
        self._links: dict[tuple[str, str, str], ExternalIdentityLink] = {}

    def save(self, link: ExternalIdentityLink) -> None:
        self._links[(link.provider_id, link.external_subject, link.tenant_id)] = link

    def get(
        self, *, provider_id: str, external_subject: str, tenant_id: str
    ) -> ExternalIdentityLink | None:
        return self._links.get((provider_id, external_subject, tenant_id))

    def _iter_links(self) -> Iterable[ExternalIdentityLink]:
        return self._links.values()


class InMemoryGroupRoleMappingRepository(GroupRoleMappingRepository):
    def __init__(self) -> None:
        self._mappings: list[GroupRoleMapping] = []

    def add(self, mapping: GroupRoleMapping) -> None:
        self._mappings.append(mapping)

    def list_for_provider(self, *, provider_id: str, tenant_id: str) -> Iterable[GroupRoleMapping]:
        return tuple(
            mapping
            for mapping in self._mappings
            if mapping.provider_id == provider_id and mapping.tenant_id == tenant_id
        )


class InMemoryClaimAttributeMappingRepository(ClaimAttributeMappingRepository):
    def __init__(self) -> None:
        self._mappings: list[ClaimAttributeMapping] = []

    def add(self, mapping: ClaimAttributeMapping) -> None:
        self._mappings.append(mapping)

    def list_for_provider(
        self, *, provider_id: str, tenant_id: str
    ) -> Iterable[ClaimAttributeMapping]:
        return tuple(
            mapping
            for mapping in self._mappings
            if mapping.provider_id == provider_id and mapping.tenant_id == tenant_id
        )


class InMemoryOIDCLoginStateRepository(OIDCLoginStateRepository):
    def __init__(self) -> None:
        self._states: dict[str, OIDCLoginState] = {}

    def save(self, state: OIDCLoginState) -> None:
        self._states[state.state_id] = state

    def get(self, state_id: str) -> OIDCLoginState | None:
        return self._states.get(state_id)

    def delete(self, state_id: str) -> None:
        self._states.pop(state_id, None)


class InMemoryFederationAuditRepository(FederationAuditRepository):
    def __init__(self) -> None:
        self._records: list[FederationAuditRecord] = []

    def save(self, record: FederationAuditRecord) -> None:
        self._records.append(record)

    def list_for_tenant(
        self, *, tenant_id: str, provider_id: str | None = None
    ) -> Iterable[FederationAuditRecord]:
        return tuple(
            record
            for record in self._records
            if record.tenant_id == tenant_id
            and (provider_id is None or record.provider_id == provider_id)
        )
