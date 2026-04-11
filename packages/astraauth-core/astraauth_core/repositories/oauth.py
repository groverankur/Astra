from astraauth_core.oauth.inmemory import (
    InMemoryAuthorizationCodeStore as InMemoryAuthorizationCodeRepository,
)
from astraauth_core.oauth.inmemory import InMemoryClientRegistry as InMemoryOAuthClientRepository
from astraauth_core.oauth.inmemory import InMemorySubjectDirectory as InMemorySubjectRepository
from astraauth_core.oauth.services import AuthorizationCodeStore as AuthorizationCodeRepository
from astraauth_core.oauth.services import ClientRegistry as OAuthClientRepository
from astraauth_core.oauth.services import SubjectDirectory as SubjectRepository

__all__ = [
    "AuthorizationCodeRepository",
    "OAuthClientRepository",
    "SubjectRepository",
    "InMemoryAuthorizationCodeRepository",
    "InMemoryOAuthClientRepository",
    "InMemorySubjectRepository",
]
