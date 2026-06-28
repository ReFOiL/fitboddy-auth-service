from domain.entities import User, UserSummary
from application.use_cases import AuthResult
from presentation.http.schemas import AuthResponse, InternalUserSummariesResponse, TokenPairResponse, UserResponse, UserSummaryResponse


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
            login=user.login,
            email=user.email,
            role=user.role,
            is_active=user.is_active,
            created_at=user.created_at,
        )

    def from_user_summaries(self, summaries: list[UserSummary]) -> InternalUserSummariesResponse:
        return InternalUserSummariesResponse(items=[self.from_user_summary(item) for item in summaries])

    @staticmethod
    def from_user_summary(summary: UserSummary) -> UserSummaryResponse:
        return UserSummaryResponse(user_id=summary.user_id, login=summary.login)
