class AuthError(Exception):
    """Base auth error."""


class TokenValidationError(AuthError):
    pass


class ConfigurationError(AuthError):
    pass


class TokenExpiredError(TokenValidationError):
    pass


class TokenVersionError(TokenValidationError):
    pass
