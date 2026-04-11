from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Protocol

from astraauth_core.oauth.models import Subject


class PasswordHashVerifier(Protocol):
    def verify(self, *, provided_password: str, stored_password_hash: str) -> bool: ...


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


class Sha256PasswordVerifier:
    def verify(self, *, provided_password: str, stored_password_hash: str) -> bool:
        calculated = hash_password(provided_password)
        return hmac.compare_digest(calculated, stored_password_hash)


@dataclass(frozen=True)
class PasswordRecord:
    username: str
    password_hash: str
    subject: Subject


class InMemoryPasswordAuthenticator:
    def __init__(self, verifier: PasswordHashVerifier) -> None:
        self._verifier = verifier
        self._records: dict[tuple[str, str], PasswordRecord] = {}

    def add(self, *, tenant_id: str, record: PasswordRecord) -> None:
        self._records[(tenant_id, record.username)] = record

    def authenticate(self, *, username: str, password: str, tenant_id: str) -> Subject | None:
        record = self._records.get((tenant_id, username))
        if record is None:
            return None

        if not self._verifier.verify(
            provided_password=password,
            stored_password_hash=record.password_hash,
        ):
            return None

        return record.subject
