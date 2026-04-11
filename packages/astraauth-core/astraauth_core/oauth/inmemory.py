from __future__ import annotations

from astraauth_core.oauth.models import AuthorizationCode, OAuthClient, Subject
from astraauth_core.oauth.services import (
    AuthorizationCodeStore,
    ClientRegistry,
    SubjectDirectory,
)


class InMemoryClientRegistry(ClientRegistry):
    def __init__(self) -> None:
        self._clients: dict[str, OAuthClient] = {}

    def add(self, client: OAuthClient) -> None:
        self._clients[client.client_id] = client

    def get_client(self, client_id: str) -> OAuthClient | None:
        return self._clients.get(client_id)


class InMemorySubjectDirectory(SubjectDirectory):
    def __init__(self) -> None:
        self._subjects: dict[str, Subject] = {}

    def add(self, subject: Subject) -> None:
        self._subjects[subject.subject_id] = subject

    def get_subject(self, subject_id: str) -> Subject | None:
        return self._subjects.get(subject_id)


class InMemoryAuthorizationCodeStore(AuthorizationCodeStore):
    def __init__(self) -> None:
        self._codes: dict[str, AuthorizationCode] = {}

    def save(self, code: AuthorizationCode) -> None:
        self._codes[code.code] = code

    def get(self, code: str) -> AuthorizationCode | None:
        return self._codes.get(code)

    def mark_used(self, code: str) -> None:
        if code in self._codes:
            self._codes[code].mark_used()
