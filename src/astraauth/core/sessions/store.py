from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Protocol

from astraauth.core.sessions.models import Session


class SessionStore(Protocol):
    def save(self, session: Session) -> None: ...
    def get(self, session_id: str) -> Session | None: ...
    def revoke(self, session_id: str) -> None: ...
    def revoke_all_for_subject(self, subject_id: str) -> None: ...
    def list_active_for_subject(self, subject_id: str) -> Iterable[Session]: ...


class BaseSessionStore(SessionStore, ABC):
    @abstractmethod
    def save(self, session: Session) -> None: ...

    @abstractmethod
    def get(self, session_id: str) -> Session | None: ...

    @abstractmethod
    def revoke(self, session_id: str) -> None: ...

    @abstractmethod
    def _iter_sessions(self) -> Iterable[Session]: ...

    def revoke_all_for_subject(self, subject_id: str) -> None:
        for session in self._iter_sessions():
            if session.subject_id == subject_id:
                self.revoke(session.session_id)

    def list_active_for_subject(self, subject_id: str) -> Iterable[Session]:
        return (
            s
            for s in self._iter_sessions()
            if s.subject_id == subject_id and not s.revoked and not s.is_expired()
        )


class InMemorySessionStore(BaseSessionStore):
    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}

    def save(self, session: Session) -> None:
        self._sessions[session.session_id] = session

    def get(self, session_id: str) -> Session | None:
        return self._sessions.get(session_id)

    def revoke(self, session_id: str) -> None:
        if session_id in self._sessions:
            self._sessions[session_id].revoked = True

    def _iter_sessions(self) -> Iterable[Session]:
        return self._sessions.values()


# Repository aliases: canonical repository naming while preserving store imports.
SessionRepository = SessionStore
BaseSessionRepository = BaseSessionStore
InMemorySessionRepository = InMemorySessionStore
