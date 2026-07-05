from astraauth.core.oauth.inmemory import (
    InMemoryAuthorizationCodeStore as InMemoryAuthorizationCodeRepository,
)
from astraauth.core.oauth.inmemory import InMemoryClientRegistry as InMemoryOAuthClientRepository
from astraauth.core.oauth.inmemory import InMemorySubjectDirectory as InMemorySubjectRepository
from astraauth.core.oauth.services import AuthorizationCodeStore as AuthorizationCodeRepository
from astraauth.core.oauth.services import ClientRegistry as OAuthClientRepository
from astraauth.core.oauth.services import SubjectDirectory as SubjectRepository

__all__ = [
    "AuthorizationCodeRepository",
    "OAuthClientRepository",
    "SubjectRepository",
    "InMemoryAuthorizationCodeRepository",
    "InMemoryOAuthClientRepository",
    "InMemorySubjectRepository",
]
