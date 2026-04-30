from domain.entities import User
from application.use_cases import AuthResult
from presentation.http.schemas import AuthResponse, TokenPairResponse, UserResponse


class AuthResponseFactory:
    def from_service_result(self, result: AuthResult) -> AuthResponse:
        return AuthResponse(
            user=self.from_domain_user(result.user),
            tokens=TokenPairResponse(
                access_token=result.tokens.access_token,
                refresh_token=result.tokens.refresh_token,
                token_type=result.tokens.token_type,
            ),
        )

    def from_domain_user(self, user: User) -> UserResponse:
        return UserResponse(
            user_id=user.user_id,
            tenant_id=user.tenant_id,
            email=user.email,
            role=user.role,
            is_active=user.is_active,
            created_at=user.created_at,
        )
