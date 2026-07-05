from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Protocol

from astraauth.core.oauth.models import Subject


class APIKeyHasher(Protocol):
    def digest(self, *, api_key: str) -> str: ...


def digest_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


class Sha256APIKeyHasher:
    def digest(self, *, api_key: str) -> str:
        # Compare-safe representation is done at match-time.
        return digest_api_key(api_key)


@dataclass(frozen=True)
class APIKeyRecord:
    key_digest: str
    subject: Subject
    revoked: bool = False


class InMemoryAPIKeyAuthenticator:
    def __init__(self, hasher: APIKeyHasher) -> None:
        self._hasher = hasher
        self._records: dict[tuple[str, str], APIKeyRecord] = {}

    def add(self, *, tenant_id: str, label: str, record: APIKeyRecord) -> None:
        self._records[(tenant_id, label)] = record

    def authenticate(self, *, api_key: str, tenant_id: str) -> Subject | None:
        key_digest = self._hasher.digest(api_key=api_key)
        matched_subject: Subject | None = None
        for (record_tenant, _), record in self._records.items():
            if record_tenant != tenant_id:
                continue
            if record.revoked:
                continue
            if hmac.compare_digest(record.key_digest, key_digest):
                matched_subject = record.subject
        return matched_subject
