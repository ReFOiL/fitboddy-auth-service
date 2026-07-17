from fastapi import HTTPException, status

from application.errors import (
    AuthError,
    ConflictError,
    ForbiddenError,
    IntegrationError,
    NotFoundError,
    UnauthorizedError,
    ValidationError,
)


class ErrorTranslator:
    def raise_http_error(self, exc: AuthError) -> None:
        if isinstance(exc, ConflictError):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        if isinstance(exc, ValidationError):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
        if isinstance(exc, UnauthorizedError):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
        if isinstance(exc, ForbiddenError):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        if isinstance(exc, NotFoundError):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        if isinstance(exc, IntegrationError):
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal auth error.") from exc
