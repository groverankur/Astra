from __future__ import annotations

import importlib
import json
from secrets import token_urlsafe
from typing import Any, Protocol

from astraauth.core.mfa.models import MFAChallenge
from astraauth.core.mfa.services import verify_mfa_challenge
from astraauth.core.mfa.store import MFAChallengeStore
from astraauth.core.sessions.models import Session
from astraauth.webauthn.models import (
    WebAuthnAuthenticationState,
    WebAuthnCredential,
    WebAuthnRegistrationState,
)
from astraauth.webauthn.store import (
    WebAuthnAuthenticationStateRepository,
    WebAuthnCredentialRepository,
    WebAuthnRegistrationStateRepository,
)


class WebAuthnChallengeGenerator(Protocol):
    def generate(self) -> str: ...


class WebAuthnVerifier(Protocol):
    def verify_registration(
        self,
        *,
        state: WebAuthnRegistrationState,
        credential_id: str,
        public_key: str,
        transports: tuple[str, ...],
        sign_count: int,
        credential_response: str | None = None,
        expected_origin: str | None = None,
        rp_id: str | None = None,
    ) -> None: ...

    def verify_authentication(
        self,
        *,
        state: WebAuthnAuthenticationState,
        credential: WebAuthnCredential,
        new_sign_count: int,
        authentication_response: str | None = None,
        expected_origin: str | None = None,
        rp_id: str | None = None,
    ) -> None: ...


class DefaultWebAuthnChallengeGenerator:
    def generate(self) -> str:
        return token_urlsafe(32)


class ProductionBaselineWebAuthnVerifier:
    def verify_registration(
        self,
        *,
        state: WebAuthnRegistrationState,
        credential_id: str,
        public_key: str,
        transports: tuple[str, ...],
        sign_count: int,
        credential_response: str | None = None,
        expected_origin: str | None = None,
        rp_id: str | None = None,
    ) -> None:
        _ = state
        if not credential_id.strip():
            raise WebAuthnVerificationError("invalid_webauthn_credential_id")
        if not public_key.strip():
            raise WebAuthnVerificationError("invalid_webauthn_public_key")
        if not transports:
            raise WebAuthnVerificationError("missing_webauthn_transports")
        if sign_count < 0:
            raise WebAuthnVerificationError("invalid_webauthn_sign_count")
        _require_ceremony_inputs(
            response=credential_response,
            expected_origin=expected_origin,
            rp_id=rp_id,
            error_code="webauthn_registration_response_required",
        )
        raise WebAuthnVerificationError("webauthn_library_not_installed")

    def verify_authentication(
        self,
        *,
        state: WebAuthnAuthenticationState,
        credential: WebAuthnCredential,
        new_sign_count: int,
        authentication_response: str | None = None,
        expected_origin: str | None = None,
        rp_id: str | None = None,
    ) -> None:
        if not state.challenge.strip():
            raise WebAuthnVerificationError("invalid_webauthn_challenge")
        if not credential.public_key.strip():
            raise WebAuthnVerificationError("invalid_webauthn_public_key")
        _validate_authentication_sign_count(
            current_sign_count=credential.sign_count,
            new_sign_count=new_sign_count,
        )
        _require_ceremony_inputs(
            response=authentication_response,
            expected_origin=expected_origin,
            rp_id=rp_id,
            error_code="webauthn_authentication_response_required",
        )
        raise WebAuthnVerificationError("webauthn_library_not_installed")


class LocalDevelopmentWebAuthnVerifier:
    def __init__(self, *, environment: str | None = None, allow_insecure: bool = False) -> None:
        normalized_environment = (environment or "").strip().lower()
        if normalized_environment in {"prod", "production"}:
            raise RuntimeError("local_development_webauthn_verifier_forbidden_in_production")
        if normalized_environment != "dev" and not allow_insecure:
            raise RuntimeError(
                "local_development_webauthn_verifier_requires_environment_dev_or_allow_insecure"
            )

    def verify_registration(
        self,
        *,
        state: WebAuthnRegistrationState,
        credential_id: str,
        public_key: str,
        transports: tuple[str, ...],
        sign_count: int,
        credential_response: str | None = None,
        expected_origin: str | None = None,
        rp_id: str | None = None,
    ) -> None:
        _ = (
            state,
            credential_id,
            public_key,
            transports,
            sign_count,
            credential_response,
            expected_origin,
            rp_id,
        )

    def verify_authentication(
        self,
        *,
        state: WebAuthnAuthenticationState,
        credential: WebAuthnCredential,
        new_sign_count: int,
        authentication_response: str | None = None,
        expected_origin: str | None = None,
        rp_id: str | None = None,
    ) -> None:
        _ = (state, credential, new_sign_count, authentication_response, expected_origin, rp_id)


class PyWebAuthnVerifier:
    def __init__(self) -> None:
        try:
            webauthn_module = importlib.import_module("webauthn")
        except ImportError as exc:
            raise RuntimeError("webauthn_library_not_installed") from exc
        self._verify_registration_response = webauthn_module.verify_registration_response
        self._verify_authentication_response = webauthn_module.verify_authentication_response

    def verify_registration(
        self,
        *,
        state: WebAuthnRegistrationState,
        credential_id: str,
        public_key: str,
        transports: tuple[str, ...],
        sign_count: int,
        credential_response: str | None = None,
        expected_origin: str | None = None,
        rp_id: str | None = None,
    ) -> None:
        _ = (credential_id, public_key, transports, sign_count)
        import base64

        credential_response = _require_ceremony_inputs(
            response=credential_response,
            expected_origin=expected_origin,
            rp_id=rp_id,
            error_code="webauthn_registration_response_required",
        )
        if expected_origin is None or rp_id is None:
            raise WebAuthnVerificationError("webauthn_registration_response_required")
        try:
            challenge_padding = len(state.challenge) % 4
            challenge_str = state.challenge + (
                "=" * (4 - challenge_padding) if challenge_padding else ""
            )
            challenge_bytes = base64.urlsafe_b64decode(challenge_str)
        except Exception:
            challenge_bytes = state.challenge.encode("utf-8")

        try:
            self._verify_registration_response(
                credential=_json_payload(credential_response),
                expected_challenge=challenge_bytes,
                expected_origin=expected_origin,
                expected_rp_id=rp_id,
            )
        except Exception as exc:
            raise WebAuthnVerificationError(
                f"webauthn_registration_verification_failed:{exc}"
            ) from exc

    def verify_authentication(
        self,
        *,
        state: WebAuthnAuthenticationState,
        credential: WebAuthnCredential,
        new_sign_count: int,
        authentication_response: str | None = None,
        expected_origin: str | None = None,
        rp_id: str | None = None,
    ) -> None:
        import base64

        authentication_response = _require_ceremony_inputs(
            response=authentication_response,
            expected_origin=expected_origin,
            rp_id=rp_id,
            error_code="webauthn_authentication_response_required",
        )
        if expected_origin is None or rp_id is None:
            raise WebAuthnVerificationError("webauthn_authentication_response_required")
        try:
            challenge_padding = len(state.challenge) % 4
            challenge_str = state.challenge + (
                "=" * (4 - challenge_padding) if challenge_padding else ""
            )
            challenge_bytes = base64.urlsafe_b64decode(challenge_str)
        except Exception:
            challenge_bytes = state.challenge.encode("utf-8")

        try:
            pubkey_padding = len(credential.public_key) % 4
            pubkey_str = credential.public_key + (
                "=" * (4 - pubkey_padding) if pubkey_padding else ""
            )
            pubkey_bytes = base64.b64decode(pubkey_str)
        except Exception:
            pubkey_bytes = credential.public_key.encode("utf-8")

        try:
            self._verify_authentication_response(
                credential=_json_payload(authentication_response),
                expected_challenge=challenge_bytes,
                expected_origin=expected_origin,
                expected_rp_id=rp_id,
                credential_public_key=pubkey_bytes,
                credential_current_sign_count=credential.sign_count,
            )
        except Exception as exc:
            raise WebAuthnVerificationError(
                f"webauthn_authentication_verification_failed:{exc}"
            ) from exc
        _validate_authentication_sign_count(
            current_sign_count=credential.sign_count,
            new_sign_count=new_sign_count,
        )


def build_default_webauthn_verifier() -> WebAuthnVerifier:
    try:
        return PyWebAuthnVerifier()
    except RuntimeError:
        return ProductionBaselineWebAuthnVerifier()


class WebAuthnError(Exception):
    pass


class WebAuthnVerificationError(WebAuthnError):
    pass


class WebAuthnRegistrationStart:
    def __init__(self, state: WebAuthnRegistrationState, options: dict[str, object]) -> None:
        self.state = state
        self.options = options


class WebAuthnAuthenticationStart:
    def __init__(self, state: WebAuthnAuthenticationState, options: dict[str, object]) -> None:
        self.state = state
        self.options = options


def _json_payload(raw: str) -> dict[str, Any]:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise WebAuthnVerificationError("invalid_webauthn_response_payload") from exc
    if not isinstance(payload, dict):
        raise WebAuthnVerificationError("invalid_webauthn_response_payload")
    return {str(key): value for key, value in payload.items()}


def _require_ceremony_inputs(
    *,
    response: str | None,
    expected_origin: str | None,
    rp_id: str | None,
    error_code: str,
) -> str:
    if response is None or expected_origin is None or rp_id is None:
        raise WebAuthnVerificationError(error_code)
    if not response.strip() or not expected_origin.strip() or not rp_id.strip():
        raise WebAuthnVerificationError(error_code)
    return response


def _validate_authentication_sign_count(*, current_sign_count: int, new_sign_count: int) -> None:
    if current_sign_count < 0 or new_sign_count < 0:
        raise WebAuthnVerificationError("invalid_webauthn_sign_count")
    if current_sign_count == 0 and new_sign_count == 0:
        return
    if new_sign_count <= current_sign_count:
        raise WebAuthnVerificationError("webauthn_sign_count_not_advanced")


def begin_registration(
    *,
    session: Session,
    user_name: str,
    rp_id: str,
    rp_name: str,
    state_repository: WebAuthnRegistrationStateRepository,
    challenge_generator: WebAuthnChallengeGenerator | None = None,
    ttl_seconds: int = 300,
) -> WebAuthnRegistrationStart:
    generator = challenge_generator or DefaultWebAuthnChallengeGenerator()
    state = WebAuthnRegistrationState.issue(
        session_id=session.session_id,
        subject_id=session.subject_id,
        tenant_id=session.tenant_id,
        challenge=generator.generate(),
        user_name=user_name,
        ttl_seconds=ttl_seconds,
    )
    state_repository.save(state)
    return WebAuthnRegistrationStart(
        state=state,
        options={
            "challenge": state.challenge,
            "rp": {"id": rp_id, "name": rp_name},
            "user": {"id": session.subject_id, "name": user_name},
        },
    )


def finish_registration(
    *,
    state_id: str,
    credential_id: str,
    public_key: str,
    transports: tuple[str, ...],
    sign_count: int,
    credential_repository: WebAuthnCredentialRepository,
    state_repository: WebAuthnRegistrationStateRepository,
    verifier: WebAuthnVerifier | None = None,
    credential_response: str | None = None,
    expected_origin: str | None = None,
    rp_id: str | None = None,
) -> WebAuthnCredential:
    state = state_repository.get(state_id)
    if state is None or state.is_expired():
        raise WebAuthnError("Invalid or expired WebAuthn registration state")
    runtime_verifier = verifier or build_default_webauthn_verifier()
    runtime_verifier.verify_registration(
        state=state,
        credential_id=credential_id,
        public_key=public_key,
        transports=transports,
        sign_count=sign_count,
        credential_response=credential_response,
        expected_origin=expected_origin,
        rp_id=rp_id,
    )
    credential = WebAuthnCredential(
        credential_id=credential_id,
        subject_id=state.subject_id,
        tenant_id=state.tenant_id,
        public_key=public_key,
        sign_count=sign_count,
        transports=transports,
        created_at=state.created_at,
    )
    credential_repository.save(credential)
    state_repository.delete(state_id)
    return credential


def begin_authentication_for_mfa(
    *,
    session: Session,
    mfa_challenge_id: str,
    credential_repository: WebAuthnCredentialRepository,
    state_repository: WebAuthnAuthenticationStateRepository,
    challenge_generator: WebAuthnChallengeGenerator | None = None,
    ttl_seconds: int = 300,
) -> WebAuthnAuthenticationStart:
    credentials = list(
        credential_repository.list_for_subject(
            subject_id=session.subject_id,
            tenant_id=session.tenant_id,
        )
    )
    if not credentials:
        raise WebAuthnError("No WebAuthn credentials registered for subject")
    generator = challenge_generator or DefaultWebAuthnChallengeGenerator()
    state = WebAuthnAuthenticationState.issue(
        mfa_challenge_id=mfa_challenge_id,
        session_id=session.session_id,
        subject_id=session.subject_id,
        tenant_id=session.tenant_id,
        challenge=generator.generate(),
        ttl_seconds=ttl_seconds,
    )
    state_repository.save(state)
    return WebAuthnAuthenticationStart(
        state=state,
        options={
            "challenge": state.challenge,
            "allowCredentials": [credential.credential_id for credential in credentials],
        },
    )


def finish_authentication_for_mfa(
    *,
    state_id: str,
    session: Session,
    credential_id: str,
    new_sign_count: int,
    credential_repository: WebAuthnCredentialRepository,
    state_repository: WebAuthnAuthenticationStateRepository,
    challenge_store: MFAChallengeStore,
    verifier: WebAuthnVerifier | None = None,
    authentication_response: str | None = None,
    expected_origin: str | None = None,
    rp_id: str | None = None,
) -> MFAChallenge:
    state = state_repository.get(state_id)
    if state is None or state.is_expired():
        raise WebAuthnError("Invalid or expired WebAuthn authentication state")
    if state.session_id != session.session_id:
        raise WebAuthnError("WebAuthn authentication state does not match session")
    credential = credential_repository.get(credential_id)
    if credential is None:
        raise WebAuthnVerificationError("Unknown WebAuthn credential")
    if credential.subject_id != session.subject_id or credential.tenant_id != session.tenant_id:
        raise WebAuthnVerificationError("WebAuthn credential does not belong to subject")
    runtime_verifier = verifier or build_default_webauthn_verifier()
    runtime_verifier.verify_authentication(
        state=state,
        credential=credential,
        new_sign_count=new_sign_count,
        authentication_response=authentication_response,
        expected_origin=expected_origin,
        rp_id=rp_id,
    )
    _validate_authentication_sign_count(
        current_sign_count=credential.sign_count,
        new_sign_count=new_sign_count,
    )
    credential.sign_count = new_sign_count
    credential_repository.save(credential)
    state_repository.delete(state_id)
    return verify_mfa_challenge(
        challenge_id=state.mfa_challenge_id,
        challenge_store=challenge_store,
        session=session,
    )
