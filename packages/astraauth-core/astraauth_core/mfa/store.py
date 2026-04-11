from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Protocol

from astraauth_core.mfa.models import EmailOTPCode, EmailOTPFactor, MFAChallenge, TOTPFactor


class MFAChallengeStore(Protocol):
    def save(self, challenge: MFAChallenge) -> None: ...
    def get(self, challenge_id: str) -> MFAChallenge | None: ...
    def list_for_session(self, session_id: str) -> Iterable[MFAChallenge]: ...


class BaseMFAChallengeStore(MFAChallengeStore, ABC):
    @abstractmethod
    def save(self, challenge: MFAChallenge) -> None: ...

    @abstractmethod
    def get(self, challenge_id: str) -> MFAChallenge | None: ...

    @abstractmethod
    def _iter_challenges(self) -> Iterable[MFAChallenge]: ...

    def list_for_session(self, session_id: str) -> Iterable[MFAChallenge]:
        return (
            challenge for challenge in self._iter_challenges() if challenge.session_id == session_id
        )


class InMemoryMFAChallengeStore(BaseMFAChallengeStore):
    def __init__(self) -> None:
        self._challenges: dict[str, MFAChallenge] = {}

    def save(self, challenge: MFAChallenge) -> None:
        self._challenges[challenge.challenge_id] = challenge

    def get(self, challenge_id: str) -> MFAChallenge | None:
        return self._challenges.get(challenge_id)

    def _iter_challenges(self) -> Iterable[MFAChallenge]:
        return self._challenges.values()


class TOTPFactorStore(Protocol):
    def save(self, factor: TOTPFactor) -> None: ...
    def get(self, factor_id: str) -> TOTPFactor | None: ...
    def get_active_for_subject(self, *, subject_id: str, tenant_id: str) -> TOTPFactor | None: ...


class BaseTOTPFactorStore(TOTPFactorStore, ABC):
    @abstractmethod
    def save(self, factor: TOTPFactor) -> None: ...

    @abstractmethod
    def get(self, factor_id: str) -> TOTPFactor | None: ...

    @abstractmethod
    def _iter_factors(self) -> Iterable[TOTPFactor]: ...

    def get_active_for_subject(self, *, subject_id: str, tenant_id: str) -> TOTPFactor | None:
        for factor in self._iter_factors():
            if factor.subject_id == subject_id and factor.tenant_id == tenant_id and factor.enabled:
                return factor
        return None


class InMemoryTOTPFactorStore(BaseTOTPFactorStore):
    def __init__(self) -> None:
        self._factors: dict[str, TOTPFactor] = {}

    def save(self, factor: TOTPFactor) -> None:
        self._factors[factor.factor_id] = factor

    def get(self, factor_id: str) -> TOTPFactor | None:
        return self._factors.get(factor_id)

    def _iter_factors(self) -> Iterable[TOTPFactor]:
        return self._factors.values()


class EmailOTPFactorStore(Protocol):
    def save(self, factor: EmailOTPFactor) -> None: ...
    def get(self, factor_id: str) -> EmailOTPFactor | None: ...
    def get_active_for_subject(self, *, subject_id: str, tenant_id: str) -> EmailOTPFactor | None: ...


class BaseEmailOTPFactorStore(EmailOTPFactorStore, ABC):
    @abstractmethod
    def save(self, factor: EmailOTPFactor) -> None: ...

    @abstractmethod
    def get(self, factor_id: str) -> EmailOTPFactor | None: ...

    @abstractmethod
    def _iter_factors(self) -> Iterable[EmailOTPFactor]: ...

    def get_active_for_subject(self, *, subject_id: str, tenant_id: str) -> EmailOTPFactor | None:
        for factor in self._iter_factors():
            if factor.subject_id == subject_id and factor.tenant_id == tenant_id and factor.enabled:
                return factor
        return None


class InMemoryEmailOTPFactorStore(BaseEmailOTPFactorStore):
    def __init__(self) -> None:
        self._factors: dict[str, EmailOTPFactor] = {}

    def save(self, factor: EmailOTPFactor) -> None:
        self._factors[factor.factor_id] = factor

    def get(self, factor_id: str) -> EmailOTPFactor | None:
        return self._factors.get(factor_id)

    def _iter_factors(self) -> Iterable[EmailOTPFactor]:
        return self._factors.values()


class EmailOTPCodeStore(Protocol):
    def save(self, code: EmailOTPCode) -> None: ...
    def get(self, challenge_id: str) -> EmailOTPCode | None: ...


class BaseEmailOTPCodeStore(EmailOTPCodeStore, ABC):
    @abstractmethod
    def save(self, code: EmailOTPCode) -> None: ...

    @abstractmethod
    def get(self, challenge_id: str) -> EmailOTPCode | None: ...


class InMemoryEmailOTPCodeStore(BaseEmailOTPCodeStore):
    def __init__(self) -> None:
        self._codes: dict[str, EmailOTPCode] = {}

    def save(self, code: EmailOTPCode) -> None:
        self._codes[code.challenge_id] = code

    def get(self, challenge_id: str) -> EmailOTPCode | None:
        return self._codes.get(challenge_id)


MFAChallengeRepository = MFAChallengeStore
BaseMFAChallengeRepository = BaseMFAChallengeStore
InMemoryMFAChallengeRepository = InMemoryMFAChallengeStore
TOTPFactorRepository = TOTPFactorStore
BaseTOTPFactorRepository = BaseTOTPFactorStore
InMemoryTOTPFactorRepository = InMemoryTOTPFactorStore
EmailOTPFactorRepository = EmailOTPFactorStore
BaseEmailOTPFactorRepository = BaseEmailOTPFactorStore
InMemoryEmailOTPFactorRepository = InMemoryEmailOTPFactorStore
EmailOTPCodeRepository = EmailOTPCodeStore
BaseEmailOTPCodeRepository = BaseEmailOTPCodeStore
InMemoryEmailOTPCodeRepository = InMemoryEmailOTPCodeStore
