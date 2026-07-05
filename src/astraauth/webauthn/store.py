from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Protocol

from astraauth.webauthn.models import (
    WebAuthnAuthenticationState,
    WebAuthnCredential,
    WebAuthnRegistrationState,
)


class WebAuthnCredentialRepository(Protocol):
    def save(self, credential: WebAuthnCredential) -> None: ...
    def get(self, credential_id: str) -> WebAuthnCredential | None: ...
    def list_for_subject(
        self, *, subject_id: str, tenant_id: str
    ) -> Iterable[WebAuthnCredential]: ...


class BaseWebAuthnCredentialRepository(WebAuthnCredentialRepository, ABC):
    @abstractmethod
    def save(self, credential: WebAuthnCredential) -> None: ...

    @abstractmethod
    def get(self, credential_id: str) -> WebAuthnCredential | None: ...

    @abstractmethod
    def _iter_credentials(self) -> Iterable[WebAuthnCredential]: ...

    def list_for_subject(self, *, subject_id: str, tenant_id: str) -> Iterable[WebAuthnCredential]:
        return (
            credential
            for credential in self._iter_credentials()
            if credential.subject_id == subject_id and credential.tenant_id == tenant_id
        )


class InMemoryWebAuthnCredentialRepository(BaseWebAuthnCredentialRepository):
    def __init__(self) -> None:
        self._credentials: dict[str, WebAuthnCredential] = {}

    def save(self, credential: WebAuthnCredential) -> None:
        self._credentials[credential.credential_id] = credential

    def get(self, credential_id: str) -> WebAuthnCredential | None:
        return self._credentials.get(credential_id)

    def _iter_credentials(self) -> Iterable[WebAuthnCredential]:
        return self._credentials.values()


class WebAuthnRegistrationStateRepository(Protocol):
    def save(self, state: WebAuthnRegistrationState) -> None: ...
    def get(self, state_id: str) -> WebAuthnRegistrationState | None: ...
    def delete(self, state_id: str) -> None: ...


class InMemoryWebAuthnRegistrationStateRepository(WebAuthnRegistrationStateRepository):
    def __init__(self) -> None:
        self._states: dict[str, WebAuthnRegistrationState] = {}

    def save(self, state: WebAuthnRegistrationState) -> None:
        self._states[state.state_id] = state

    def get(self, state_id: str) -> WebAuthnRegistrationState | None:
        return self._states.get(state_id)

    def delete(self, state_id: str) -> None:
        self._states.pop(state_id, None)


class WebAuthnAuthenticationStateRepository(Protocol):
    def save(self, state: WebAuthnAuthenticationState) -> None: ...
    def get(self, state_id: str) -> WebAuthnAuthenticationState | None: ...
    def delete(self, state_id: str) -> None: ...


class InMemoryWebAuthnAuthenticationStateRepository(WebAuthnAuthenticationStateRepository):
    def __init__(self) -> None:
        self._states: dict[str, WebAuthnAuthenticationState] = {}

    def save(self, state: WebAuthnAuthenticationState) -> None:
        self._states[state.state_id] = state

    def get(self, state_id: str) -> WebAuthnAuthenticationState | None:
        return self._states.get(state_id)

    def delete(self, state_id: str) -> None:
        self._states.pop(state_id, None)
