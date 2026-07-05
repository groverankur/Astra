import json
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from joserfc import jwe, jwk, jws
from joserfc.jwt import JWTClaimsRegistry

from astraauth.core.config.settings import AuthConfig
from astraauth.core.errors import (
    TokenExpiredError,
    TokenValidationError,
    TokenVersionError,
)
from astraauth.core.ids import uuid7_str
from astraauth.core.token.store import InMemoryKeyStore, KeyMetadata
from astraauth.core.version import TOKEN_SCHEMA_VERSION


def _string_field(payload: dict[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise ValueError(f"token key {key} is required")
    return value


def _int_field(payload: dict[str, object], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int):
        raise ValueError(f"token key {key} is required")
    return value


def _bool_field(payload: dict[str, object], key: str) -> bool:
    value = payload.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"token key {key} is required")
    return value


def _private_jwk_payload(payload: dict[object, object]) -> dict[str, str | list[str]]:
    result: dict[str, str | list[str]] = {}
    for key, value in payload.items():
        if not isinstance(key, str):
            raise ValueError("private jwk keys must be strings")
        if key == "is_private":
            continue
        if isinstance(value, str):
            result[key] = value
        elif isinstance(value, list) and all(isinstance(item, str) for item in value):
            result[key] = [str(item) for item in value]
        else:
            raise ValueError("private jwk values must be strings or string lists")
    return result


class TokenKeyManager:
    """
    SINGLE authority for:
    - JWT (JWS) issuance & verification
    - JWE issuance & decryption
    - Key rotation
    - JWK exposure
    """

    _JWT_CLAIMS_REGISTRY = JWTClaimsRegistry(
        iss={"essential": True},
        sub={"essential": True},
        aud={"essential": True},
        exp={"essential": True},
        iat={"essential": True},
        nbf={"essential": False},
        jti={"essential": True},
        ver={"essential": True},
    )

    _KEY_STATE_VERSION = 1

    def __init__(
        self, config: AuthConfig, *, serialized_state: dict[str, Any] | None = None
    ) -> None:
        config.validate_settings()
        self._config = config
        self._store = InMemoryKeyStore()
        if serialized_state is None:
            self._bootstrap_keys()
        else:
            self._restore_state(serialized_state)

    def _bootstrap_keys(self) -> None:
        now = datetime.now(tz=UTC)

        sig_key = jwk.RSAKey.generate_key(2048)
        sig_kid = uuid7_str()
        self._store.add_key(
            sig_key,
            KeyMetadata(
                kid=sig_kid,
                version=1,
                created_at=now,
                expires_at=None,
                use="sig",
                alg="RS256",
                active=True,
            ),
        )

        enc_key = jwk.RSAKey.generate_key(2048)
        enc_kid = uuid7_str()
        self._store.add_key(
            enc_key,
            KeyMetadata(
                kid=enc_kid,
                version=1,
                created_at=now,
                expires_at=None,
                use="enc",
                alg=self._config.encryption_alg,
                active=True,
            ),
        )

    def rotate_keys(self, *, use: str) -> None:
        now = datetime.now(tz=UTC)

        if use == "sig":
            key = jwk.RSAKey.generate_key(2048)
            alg = self._config.signing_alg
        elif use == "enc":
            key = jwk.RSAKey.generate_key(2048)
            alg = self._config.encryption_alg
        else:
            raise ValueError("use must be 'sig' or 'enc'")

        kid = uuid7_str()
        meta = KeyMetadata(
            kid=kid,
            version=1,
            created_at=now,
            expires_at=None,
            use=use,
            alg=alg,
            active=True,
        )
        self._store.add_key(key, meta)

    def dump_private_state(self) -> dict[str, Any]:
        records = []
        for key, meta in self._store.all_key_records():
            records.append(
                {
                    "private_jwk": key.as_dict(is_private=True),
                    "metadata": {
                        "kid": meta.kid,
                        "version": meta.version,
                        "created_at": meta.created_at.isoformat(),
                        "expires_at": meta.expires_at.isoformat() if meta.expires_at else None,
                        "use": meta.use,
                        "alg": meta.alg,
                        "active": meta.active,
                    },
                }
            )
        return {"version": self._KEY_STATE_VERSION, "keys": records}

    def _restore_state(self, payload: dict[str, Any]) -> None:
        if int(payload.get("version", 0)) != self._KEY_STATE_VERSION:
            raise ValueError("unsupported token key state version")
        raw_keys = payload.get("keys")
        if not isinstance(raw_keys, list) or not raw_keys:
            raise ValueError("token key state must contain keys")

        def _sort_key(item: object) -> str:
            if not isinstance(item, dict):
                return ""
            metadata = item.get("metadata")
            if not isinstance(metadata, dict):
                return ""
            created_at = metadata.get("created_at")
            return str(created_at) if created_at is not None else ""

        for item in sorted(raw_keys, key=_sort_key):
            if not isinstance(item, dict):
                raise ValueError("token key entry must be an object")
            private_jwk = item.get("private_jwk")
            metadata = item.get("metadata")
            if not isinstance(private_jwk, dict) or not isinstance(metadata, dict):
                raise ValueError("token key entry is invalid")
            private_jwk_payload = _private_jwk_payload(cast(dict[object, object], private_jwk))
            metadata_payload = {str(key): value for key, value in metadata.items()}
            key = jwk.import_key(private_jwk_payload)
            created_at = _string_field(metadata_payload, "created_at")
            expires_at = metadata_payload.get("expires_at")
            meta = KeyMetadata(
                kid=_string_field(metadata_payload, "kid"),
                version=_int_field(metadata_payload, "version"),
                created_at=datetime.fromisoformat(created_at),
                expires_at=datetime.fromisoformat(expires_at)
                if isinstance(expires_at, str)
                else None,
                use=_string_field(metadata_payload, "use"),
                alg=_string_field(metadata_payload, "alg"),
                active=_bool_field(metadata_payload, "active"),
            )
            self._store.add_key(key, meta)

    def _build_base_claims(
        self,
        *,
        subject: str,
        audience: str,
        ttl_seconds: int,
    ) -> dict[str, Any]:
        now = datetime.now(tz=UTC)
        return {
            "iss": self._config.issuer,
            "sub": subject,
            "aud": audience,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
            "jti": uuid7_str(),
            "ver": TOKEN_SCHEMA_VERSION,
        }

    def _validate_claims(self, payload: dict[str, Any], *, audience: str) -> None:
        self._JWT_CLAIMS_REGISTRY.validate(payload)

        now = int(datetime.now(tz=UTC).timestamp())

        if payload.get("iss") != self._config.issuer:
            raise TokenValidationError("Invalid issuer")

        if payload.get("aud") != audience:
            raise TokenValidationError("Invalid audience")

        token_version = payload.get("ver")
        if not isinstance(token_version, int) or token_version < TOKEN_SCHEMA_VERSION:
            raise TokenVersionError("Unsupported token version")

        exp = payload.get("exp")
        if exp is not None and now > exp + self._config.clock_skew_seconds:
            raise TokenExpiredError("Token expired")

        nbf = payload.get("nbf")
        if nbf is not None and now + self._config.clock_skew_seconds < nbf:
            raise TokenValidationError("Token not yet valid")

    def issue_jwt(
        self,
        *,
        subject: str,
        audience: str,
        extra_claims: dict[str, Any] | None = None,
        ttl_seconds: int | None = None,
    ) -> str:
        payload = self._build_base_claims(
            subject=subject,
            audience=audience,
            ttl_seconds=ttl_seconds or self._config.access_token_ttl_seconds,
        )

        if extra_claims:
            payload.update(extra_claims)

        key, meta = self._store.get_active("sig")

        if meta.use != "sig":
            raise RuntimeError("Active key is not a signing key")

        return jws.serialize_compact(
            protected={"alg": meta.alg, "kid": meta.kid},
            payload=json.dumps(payload),
            private_key=key,
        )

    def verify_jwt(self, token: str, *, audience: str) -> dict[str, Any]:
        from json import loads

        last_error: Exception | None = None
        for pub_key in self._store.all_public_keys():
            try:
                obj = jws.deserialize_compact(token, pub_key)
                raw_payload = obj.payload
                payload = (
                    loads(raw_payload) if isinstance(raw_payload, (bytes, str)) else raw_payload
                )
                payload = cast(dict[str, Any], payload)
                self._validate_claims(payload, audience=audience)
                return payload
            except Exception as exc:
                last_error = exc
                continue

        raise TokenValidationError("Invalid or unverifiable JWT") from last_error

    def issue_jwe(self, payload: dict[str, Any]) -> str:
        key, meta = self._store.get_active("enc")

        if meta.use != "enc":
            raise RuntimeError("Active key is not an encryption key")

        protected = {
            "alg": meta.alg,
            "enc": self._config.encryption_enc,
            "kid": meta.kid,
        }
        payload_bytes = json.dumps(payload).encode("utf-8")
        return jwe.encrypt_compact(protected, payload_bytes, key)

    def decrypt_jwe(self, token: str) -> dict[str, Any]:
        last_error: Exception | None = None
        for priv_key in self._store.all_private_keys():
            try:
                obj = jwe.decrypt_compact(token, priv_key)
                payload_bytes = obj.plaintext
                if payload_bytes is None:
                    raise TokenValidationError("Empty JWE plaintext")
                if isinstance(payload_bytes, bytes):
                    payload_str = payload_bytes.decode("utf-8")
                else:
                    payload_str = payload_bytes
                payload = cast(dict[str, Any], json.loads(payload_str))
                return payload
            except Exception as exc:
                last_error = exc
                continue

        raise TokenValidationError("Invalid or undecryptable JWE token") from last_error

    def get_jwks(self) -> list[dict[str, Any]]:
        return [key.as_dict(is_private=False) for key in self._store.all_public_keys()]
