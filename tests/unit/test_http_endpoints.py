from fastapi.testclient import TestClient
import pytest

from presentation.http.main import app  # type: ignore[import-not-found]


@pytest.fixture()
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


def test_health(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_ready(client: TestClient) -> None:
    response = client.get("/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_register_and_me(client: TestClient) -> None:
    register_response = client.post(
        "/api/v1/auth/register",
        json={
            "login": "user1_login",
            "email": "user1@example.com",
            "password": "MyStrongPass123",
            "role": "trainer",
        },
    )
    assert register_response.status_code == 201
    data = register_response.json()
    access_token = data["tokens"]["access_token"]

    me_response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert me_response.status_code == 200
    assert me_response.json()["tenant_id"] == "marketplace"
    assert me_response.json()["login"] == "user1_login"
    assert me_response.json()["email"] == "user1@example.com"


def test_refresh_and_logout_flow(client: TestClient) -> None:
    register_response = client.post(
        "/api/v1/auth/register",
        json={
            "login": "user2_login",
            "email": "user2@example.com",
            "password": "MyStrongPass123",
            "role": "client",
        },
    )
    refresh_token = register_response.json()["tokens"]["refresh_token"]

    refresh_response = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert refresh_response.status_code == 200
    refreshed_token = refresh_response.json()["refresh_token"]

    logout_response = client.post("/api/v1/auth/logout", json={"refresh_token": refreshed_token})
    assert logout_response.status_code == 204

    second_refresh = client.post("/api/v1/auth/refresh", json={"refresh_token": refreshed_token})
    assert second_refresh.status_code == 401


def test_login_with_wrong_password_returns_401(client: TestClient) -> None:
    register_response = client.post(
        "/api/v1/auth/register",
        json={
            "login": "user3_login",
            "email": "user3@example.com",
            "password": "MyStrongPass123",
            "role": "client",
        },
    )
    assert register_response.status_code == 201

    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email_or_login": "user3@example.com",
            "password": "WrongPass123",
        },
    )
    assert login_response.status_code == 401


def test_login_with_login_returns_200(client: TestClient) -> None:
    register_response = client.post(
        "/api/v1/auth/register",
        json={
            "login": "user4_login",
            "email": "user4@example.com",
            "password": "MyStrongPass123",
            "role": "client",
        },
    )
    assert register_response.status_code == 201

    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email_or_login": "USER4_LOGIN",
            "password": "MyStrongPass123",
        },
    )
    assert login_response.status_code == 200
    payload = login_response.json()
    assert payload["user"]["login"] == "user4_login"
    assert payload["user"]["email"] == "user4@example.com"


def test_login_with_legacy_email_field_returns_422(client: TestClient) -> None:
    register_response = client.post(
        "/api/v1/auth/register",
        json={
            "login": "user5_login",
            "email": "user5@example.com",
            "password": "MyStrongPass123",
            "role": "trainer",
        },
    )
    assert register_response.status_code == 201

    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "USER5@EXAMPLE.COM",
            "password": "MyStrongPass123",
        },
    )
    assert login_response.status_code == 422


def test_register_duplicate_email_returns_409(client: TestClient) -> None:
    first_payload = {
        "login": "dup_email_1",
        "email": "dup@example.com",
        "password": "MyStrongPass123",
        "role": "client",
    }
    second_payload = {
        "login": "dup_email_2",
        "email": "dup@example.com",
        "password": "MyStrongPass123",
        "role": "trainer",
    }
    first_response = client.post("/api/v1/auth/register", json=first_payload)
    assert first_response.status_code == 201

    second_response = client.post("/api/v1/auth/register", json=second_payload)
    assert second_response.status_code == 409
    assert "email" in second_response.json()["detail"].lower()


def test_register_duplicate_login_returns_409(client: TestClient) -> None:
    first_payload = {
        "login": "same_login",
        "email": "same-login-1@example.com",
        "password": "MyStrongPass123",
        "role": "client",
    }
    second_payload = {
        "login": "same_login",
        "email": "same-login-2@example.com",
        "password": "MyStrongPass123",
        "role": "trainer",
    }
    first_response = client.post("/api/v1/auth/register", json=first_payload)
    assert first_response.status_code == 201

    second_response = client.post("/api/v1/auth/register", json=second_payload)
    assert second_response.status_code == 409
    assert "login" in second_response.json()["detail"].lower()


def test_register_parallel_same_email_only_one_succeeds() -> None:
    from concurrent.futures import ThreadPoolExecutor

    from sqlalchemy import func, select

    from application.commands import RegisterUserCommand
    from application.config import Settings
    from application.errors import ConflictError
    from application.models import UserModel
    from application.runtime import AuthApplicationRuntime

    runtime = AuthApplicationRuntime(Settings())
    email = "race-parallel@example.com"

    def register(index: int) -> bool:
        try:
            with runtime.auth_service_scope() as auth_service:
                auth_service.register_user(
                    RegisterUserCommand(
                        role="client",
                        login=f"race_par_{index}",
                        email=email,
                        password="MyStrongPass123",
                    )
                )
            return True
        except ConflictError:
            return False

    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(register, range(8)))
        assert outcomes.count(True) == 1
        assert outcomes.count(False) == 7

        session = runtime._database.create_session()
        try:
            total = session.execute(
                select(func.count()).select_from(UserModel).where(UserModel.email == email)
            ).scalar_one()
            assert total == 1
        finally:
            session.close()
    finally:
        runtime.shutdown()


def test_me_without_bearer_token_returns_401(client: TestClient) -> None:
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401


def test_refresh_with_invalid_token_returns_401(client: TestClient) -> None:
    response = client.post("/api/v1/auth/refresh", json={"refresh_token": "not-a-valid-token"})
    assert response.status_code == 401


def test_check_with_valid_access_token_returns_user(client: TestClient) -> None:
    register_response = client.post(
        "/api/v1/auth/register",
        json={
            "login": "check_login",
            "email": "check@example.com",
            "password": "MyStrongPass123",
            "role": "client",
        },
    )
    assert register_response.status_code == 201
    access_token = register_response.json()["tokens"]["access_token"]

    check_response = client.post("/api/v1/auth/check", json={"access_token": access_token})
    assert check_response.status_code == 200
    assert check_response.json()["tenant_id"] == "marketplace"
    assert check_response.json()["login"] == "check_login"
    assert check_response.json()["email"] == "check@example.com"


def test_check_with_invalid_access_token_returns_401(client: TestClient) -> None:
    check_response = client.post("/api/v1/auth/check", json={"access_token": "bad-token"})
    assert check_response.status_code == 401


def test_internal_summaries_returns_logins_by_user_ids(client: TestClient) -> None:
    first_user = client.post(
        "/api/v1/auth/register",
        json={
            "login": "summary_login_1",
            "email": "summary-1@example.com",
            "password": "MyStrongPass123",
            "role": "client",
        },
    )
    second_user = client.post(
        "/api/v1/auth/register",
        json={
            "login": "summary_login_2",
            "email": "summary-2@example.com",
            "password": "MyStrongPass123",
            "role": "trainer",
        },
    )
    assert first_user.status_code == 201
    assert second_user.status_code == 201

    first_user_id = first_user.json()["user"]["user_id"]
    second_user_id = second_user.json()["user"]["user_id"]
    response = client.post(
        "/api/v1/auth/internal/summaries",
        json={"user_ids": [first_user_id, second_user_id, "missing-user"]},
    )
    assert response.status_code == 200
    payload = response.json()
    items = payload["items"]
    assert any(item["user_id"] == first_user_id and item["login"] == "summary_login_1" for item in items)
    assert any(item["user_id"] == second_user_id and item["login"] == "summary_login_2" for item in items)


def test_admin_users_requires_platform_admin(client: TestClient) -> None:
    register_response = client.post(
        "/api/v1/auth/register",
        json={
            "login": "regular_user",
            "email": "regular@example.com",
            "password": "MyStrongPass123",
            "role": "client",
        },
    )
    assert register_response.status_code == 201
    access_token = register_response.json()["tokens"]["access_token"]

    response = client.get(
        "/api/v1/admin/users",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert response.status_code == 403


def test_admin_users_list_and_patch(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PLATFORM_ADMIN_LOGIN", "platform_admin")
    monkeypatch.setenv("PLATFORM_ADMIN_PASSWORD", "AdminPass123")
    monkeypatch.setenv("PLATFORM_ADMIN_EMAIL", "admin@example.com")

    from application.commands import BootstrapPlatformAdminCommand
    from application.config import Settings
    from application.runtime import AuthApplicationRuntime

    runtime = AuthApplicationRuntime(Settings())
    with runtime.auth_service_scope() as auth_service:
        created, action = auth_service.bootstrap_platform_admin(
            BootstrapPlatformAdminCommand(
                login="platform_admin",
                email="admin@example.com",
                password="AdminPass123",
            )
        )
        assert created is not None
        assert action == "created"
    runtime.shutdown()

    login_response = client.post(
        "/api/v1/auth/login",
        json={"email_or_login": "platform_admin", "password": "AdminPass123"},
    )
    assert login_response.status_code == 200
    admin_token = login_response.json()["tokens"]["access_token"]
    assert login_response.json()["user"]["role"] == "platform_admin"

    target = client.post(
        "/api/v1/auth/register",
        json={
            "login": "target_user",
            "email": "target@example.com",
            "password": "MyStrongPass123",
            "role": "trainer",
        },
    )
    assert target.status_code == 201
    target_id = target.json()["user"]["user_id"]

    list_response = client.get(
        "/api/v1/admin/users",
        headers={"Authorization": f"Bearer {admin_token}"},
        params={"q": "target_user"},
    )
    assert list_response.status_code == 200
    payload = list_response.json()
    assert payload["total"] >= 1
    assert any(item["user_id"] == target_id for item in payload["items"])

    patch_response = client.patch(
        f"/api/v1/admin/users/{target_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"is_active": False, "role": "client"},
    )
    assert patch_response.status_code == 200
    assert patch_response.json()["is_active"] is False
    assert patch_response.json()["role"] == "client"