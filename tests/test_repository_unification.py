from astraauth.core.mfa import InMemoryMFAChallengeStore
from astraauth.core.plugins import InMemoryTenantPluginRegistryStore
from astraauth.core.repositories import (
    InMemoryAuthorizationCodeRepository,
    InMemoryMFAChallengeRepository,
    InMemoryOAuthClientRepository,
    InMemorySessionRepository,
    InMemorySubjectRepository,
    InMemoryTenantPluginRegistryRepository,
    MFAChallengeRepository,
    OAuthClientRepository,
    RoleAssignmentRepository,
    RoleRepository,
    SessionRepository,
    SQLSessionRepository,
    SQLTenantPluginRegistryRepository,
    SubjectRepository,
    TenantPluginRegistryRepository,
)
from astraauth.core.sessions import InMemorySessionStore


def test_repository_layer_exports_canonical_aliases() -> None:
    session_repo = InMemorySessionRepository()
    assert isinstance(session_repo, InMemorySessionStore)

    challenge_repo = InMemoryMFAChallengeRepository()
    assert isinstance(challenge_repo, InMemoryMFAChallengeStore)

    plugin_repo = InMemoryTenantPluginRegistryRepository()
    assert isinstance(plugin_repo, InMemoryTenantPluginRegistryStore)

    assert SessionRepository.__name__ == "SessionStore"
    assert MFAChallengeRepository.__name__ == "MFAChallengeStore"
    assert TenantPluginRegistryRepository.__name__ == "TenantPluginRegistryStore"
    assert RoleRepository.__name__ == "RoleStore"
    assert RoleAssignmentRepository.__name__ == "AssignmentStore"
    assert OAuthClientRepository.__name__ == "ClientRegistry"
    assert SubjectRepository.__name__ == "SubjectDirectory"


def test_repository_layer_exposes_backend_aliases() -> None:
    assert InMemoryAuthorizationCodeRepository.__name__ == "InMemoryAuthorizationCodeStore"
    assert InMemoryOAuthClientRepository.__name__ == "InMemoryClientRegistry"
    assert InMemorySubjectRepository.__name__ == "InMemorySubjectDirectory"
    assert SQLSessionRepository.__name__ == "SQLSessionStore"
    assert SQLTenantPluginRegistryRepository.__name__ == "SQLTenantPluginRegistryStore"
