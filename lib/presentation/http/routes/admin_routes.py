from fastapi import APIRouter, Header, Query, Request

from presentation.http.schemas import PatchUserRequest, UserListResponse, UserResponse


class AdminRoutes:
    def __init__(self) -> None:
        self.router = APIRouter(prefix="/api/v1/admin", tags=["admin"])
        self.router.add_api_route("/users", self.list_users, methods=["GET"], response_model=UserListResponse)
        self.router.add_api_route("/users/{user_id}", self.get_user, methods=["GET"], response_model=UserResponse)
        self.router.add_api_route("/users/{user_id}", self.patch_user, methods=["PATCH"], response_model=UserResponse)

    def list_users(
        self,
        request: Request,
        authorization: str = Header(default="", alias="Authorization"),
        q: str | None = Query(default=None),
        role: str | None = Query(default=None),
        is_active: bool | None = Query(default=None),
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=20, ge=1, le=100),
    ) -> UserListResponse:
        return request.app.state.auth_handler.list_users(
            authorization=authorization,
            query=q,
            role=role,
            is_active=is_active,
            page=page,
            page_size=page_size,
        )

    def get_user(
        self,
        user_id: str,
        request: Request,
        authorization: str = Header(default="", alias="Authorization"),
    ) -> UserResponse:
        return request.app.state.auth_handler.get_user(authorization=authorization, user_id=user_id)

    def patch_user(
        self,
        user_id: str,
        payload: PatchUserRequest,
        request: Request,
        authorization: str = Header(default="", alias="Authorization"),
    ) -> UserResponse:
        return request.app.state.auth_handler.patch_user(
            authorization=authorization,
            user_id=user_id,
            payload=payload,
        )
