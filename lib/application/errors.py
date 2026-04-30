class AuthError(Exception):
    pass


class ConflictError(AuthError):
    pass


class UnauthorizedError(AuthError):
    pass


class ValidationError(AuthError):
    pass


class IntegrationError(AuthError):
    pass
