from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Protocol

from pwdlib import PasswordHash

from astraauth.core.oauth.models import Subject

_PASSWORD_HASHER = PasswordHash.recommended()


class PasswordHashVerifier(Protocol):
    def verify_and_update(
        self,
        *,
        provided_password: str,
        stored_password_hash: str,
    ) -> tuple[bool, str | None]: ...

    def verify(self, *, provided_password: str, stored_password_hash: str) -> bool: ...
    def needs_rehash(self, *, stored_password_hash: str) -> bool: ...


def hash_password_legacy_sha256(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def is_legacy_sha256_password_hash(stored_password_hash: str) -> bool:
    return len(stored_password_hash) == 64 and all(
        character in "0123456789abcdef" for character in stored_password_hash.lower()
    )


def hash_password(password: str) -> str:
    return _PASSWORD_HASHER.hash(password)


class Argon2PasswordVerifier:
    def verify_and_update(
        self,
        *,
        provided_password: str,
        stored_password_hash: str,
    ) -> tuple[bool, str | None]:
        try:
            return _PASSWORD_HASHER.verify_and_update(provided_password, stored_password_hash)
        except Exception:
            return False, None

    def verify(self, *, provided_password: str, stored_password_hash: str) -> bool:
        valid, _ = self.verify_and_update(
            provided_password=provided_password,
            stored_password_hash=stored_password_hash,
        )
        return valid

    def needs_rehash(self, *, stored_password_hash: str) -> bool:
        return not stored_password_hash.startswith("$argon2")


class Sha256PasswordVerifier:
    def verify_and_update(
        self,
        *,
        provided_password: str,
        stored_password_hash: str,
    ) -> tuple[bool, str | None]:
        valid = self.verify(
            provided_password=provided_password,
            stored_password_hash=stored_password_hash,
        )
        if not valid:
            return False, None
        return True, hash_password(provided_password)

    def verify(self, *, provided_password: str, stored_password_hash: str) -> bool:
        calculated = hash_password_legacy_sha256(provided_password)
        return hmac.compare_digest(calculated, stored_password_hash)

    def needs_rehash(self, *, stored_password_hash: str) -> bool:
        _ = stored_password_hash
        return True


class MultiSchemePasswordVerifier:
    def __init__(self) -> None:
        self._argon2 = Argon2PasswordVerifier()
        self._sha256 = Sha256PasswordVerifier()

    def verify_and_update(
        self,
        *,
        provided_password: str,
        stored_password_hash: str,
    ) -> tuple[bool, str | None]:
        if is_legacy_sha256_password_hash(stored_password_hash):
            return self._sha256.verify_and_update(
                provided_password=provided_password,
                stored_password_hash=stored_password_hash,
            )
        return self._argon2.verify_and_update(
            provided_password=provided_password,
            stored_password_hash=stored_password_hash,
        )

    def verify(self, *, provided_password: str, stored_password_hash: str) -> bool:
        valid, _ = self.verify_and_update(
            provided_password=provided_password,
            stored_password_hash=stored_password_hash,
        )
        return valid

    def needs_rehash(self, *, stored_password_hash: str) -> bool:
        if is_legacy_sha256_password_hash(stored_password_hash):
            return True
        return self._argon2.needs_rehash(stored_password_hash=stored_password_hash)


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

        valid, upgraded_hash = self._verifier.verify_and_update(
            provided_password=password,
            stored_password_hash=record.password_hash,
        )
        if not valid:
            return None
        if upgraded_hash is not None and upgraded_hash != record.password_hash:
            self._records[(tenant_id, username)] = PasswordRecord(
                username=record.username,
                password_hash=upgraded_hash,
                subject=record.subject,
            )

        return record.subject

    def needs_rehash(self, *, username: str, tenant_id: str) -> bool:
        record = self._records.get((tenant_id, username))
        if record is None:
            return False
        return self._verifier.needs_rehash(stored_password_hash=record.password_hash)
