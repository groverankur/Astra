from __future__ import annotations

from secrets import token_urlsafe
from typing import Protocol

from astraauth_core.mfa.models import MFAChallenge
from astraauth_core.mfa.services import verify_mfa_challenge
from astraauth_core.mfa.store import MFAChallengeStore
from astraauth_core.sessions.models import Session

from astraauth_webauthn.models import (
    WebAuthnAuthenticationState,
    WebAuthnCredential,
    WebAuthnRegistrationState,
)
from astraauth_webauthn.store import (
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
    ) -> None: ...

    def verify_authentication(
        self,
        *,
        state: WebAuthnAuthenticationState,
        credential: WebAuthnCredential,
        new_sign_count: int,
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

    def verify_authentication(
        self,
        *,
        state: WebAuthnAuthenticationState,
        credential: WebAuthnCredential,
        new_sign_count: int,
    ) -> None:
        if not state.challenge.strip():
            raise WebAuthnVerificationError("invalid_webauthn_challenge")
        if not credential.public_key.strip():
            raise WebAuthnVerificationError("invalid_webauthn_public_key")
        if new_sign_count <= credential.sign_count:
            raise WebAuthnVerificationError("webauthn_sign_count_not_advanced")


class LocalDevelopmentWebAuthnVerifier:
    def verify_registration(
        self,
        *,
        state: WebAuthnRegistrationState,
        credential_id: str,
        public_key: str,
        transports: tuple[str, ...],
        sign_count: int,
    ) -> None:
        _ = (state, credential_id, public_key, transports, sign_count)

    def verify_authentication(
        self,
        *,
        state: WebAuthnAuthenticationState,
        credential: WebAuthnCredential,
        new_sign_count: int,
    ) -> None:
        _ = (state, credential, new_sign_count)


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
) -> WebAuthnCredential:
    state = state_repository.get(state_id)
    if state is None or state.is_expired():
        raise WebAuthnError("Invalid or expired WebAuthn registration state")
    if verifier is not None:
        verifier.verify_registration(
            state=state,
            credential_id=credential_id,
            public_key=public_key,
            transports=transports,
            sign_count=sign_count,
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
    if verifier is not None:
        verifier.verify_authentication(
            state=state,
            credential=credential,
            new_sign_count=new_sign_count,
        )
    if new_sign_count < credential.sign_count:
        raise WebAuthnVerificationError("WebAuthn sign counter regression detected")
    credential.sign_count = new_sign_count
    credential_repository.save(credential)
    state_repository.delete(state_id)
    return verify_mfa_challenge(
        challenge_id=state.mfa_challenge_id,
        challenge_store=challenge_store,
        session=session,
    )
