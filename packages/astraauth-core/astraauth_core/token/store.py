from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from joserfc import jwk


@dataclass
class KeyMetadata:
    kid: str
    version: int
    created_at: datetime
    expires_at: datetime | None
    use: str  # "sig" or "enc"
    alg: str
    active: bool = False


class KeyStore(Protocol):
    def add_key(self, key: jwk.Key, meta: KeyMetadata) -> None: ...
    def get_key(self, kid: str) -> jwk.Key | None: ...
    def get_metadata(self, kid: str) -> KeyMetadata | None: ...
    def set_active(self, kid: str, use: str) -> None: ...
    def get_active(self, use: str) -> tuple[jwk.Key, KeyMetadata]: ...
    def all_public_keys(self) -> Iterable[jwk.Key]: ...
    def all_private_keys(self) -> Iterable[jwk.Key]: ...


class InMemoryKeyStore:
    def __init__(self) -> None:
        self._keys: dict[str, jwk.Key] = {}
        self._meta: dict[str, KeyMetadata] = {}
        self._active_sig: str | None = None
        self._active_enc: str | None = None

    def add_key(self, key: jwk.Key, meta: KeyMetadata) -> None:
        self._keys[meta.kid] = key
        self._meta[meta.kid] = meta
        if meta.active:
            self.set_active(meta.kid, meta.use)

    def get_key(self, kid: str) -> jwk.Key | None:
        return self._keys.get(kid)

    def get_metadata(self, kid: str) -> KeyMetadata | None:
        return self._meta.get(kid)

    def set_active(self, kid: str, use: str) -> None:
        if kid not in self._keys:
            raise ValueError(f"Unknown kid={kid}")

        if use not in ("sig", "enc"):
            raise ValueError("use must be 'sig' or 'enc'")

        # Deactivate previous active key for this use
        prev_kid = self._active_sig if use == "sig" else self._active_enc
        if prev_kid and prev_kid in self._meta:
            prev_meta = self._meta[prev_kid]
            self._meta[prev_kid] = KeyMetadata(**{**prev_meta.__dict__, "active": False})

        # Set new active key
        if use == "sig":
            self._active_sig = kid
        else:
            self._active_enc = kid

        meta = self._meta[kid]
        self._meta[kid] = KeyMetadata(**{**meta.__dict__, "active": True})

    def _is_expired(self, meta: KeyMetadata) -> bool:
        if meta.expires_at is None:
            return False
        now = datetime.now(tz=UTC)
        return meta.expires_at < now

    def get_active(self, use: str) -> tuple[jwk.Key, KeyMetadata]:
        if use not in ("sig", "enc"):
            raise ValueError("use must be 'sig' or 'enc'")

        kid = self._active_sig if use == "sig" else self._active_enc
        if not kid:
            raise RuntimeError(f"No active {use} key configured")

        meta = self._meta[kid]
        if self._is_expired(meta):
            raise RuntimeError(f"Active {use} key is expired")

        key = self._keys[kid]
        return key, meta

    def all_public_keys(self) -> Iterable[jwk.Key]:
        now = datetime.now(tz=UTC)
        for kid, key in self._keys.items():
            meta = self._meta[kid]
            if meta.expires_at and meta.expires_at < now:
                continue
            yield jwk.import_key(key.as_dict(is_private=False))

    def all_private_keys(self) -> Iterable[jwk.Key]:
        now = datetime.now(tz=UTC)
        for kid, key in self._keys.items():
            meta = self._meta[kid]
            if meta.expires_at and meta.expires_at < now:
                continue
            yield key

    def all_key_records(self) -> Iterable[tuple[jwk.Key, KeyMetadata]]:
        for kid, key in self._keys.items():
            yield key, self._meta[kid]
