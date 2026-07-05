from __future__ import annotations


class OAuthError(Exception):
    """
    Base class for OAuth/OIDC domain errors.
    """

    error: str = "invalid_request"
    description: str = "OAuth error"

    def __init__(self, description: str | None = None) -> None:
        if description:
            self.description = description
        super().__init__(self.description)


class InvalidRequestError(OAuthError):
    error = "invalid_request"


class InvalidClientError(OAuthError):
    error = "invalid_client"


class InvalidGrantError(OAuthError):
    error = "invalid_grant"


class UnauthorizedClientError(OAuthError):
    error = "unauthorized_client"


class UnsupportedGrantTypeError(OAuthError):
    error = "unsupported_grant_type"


class AccessDeniedError(OAuthError):
    error = "access_denied"
