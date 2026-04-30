from fastapi.testclient import TestClient

from presentation.http.main import app  # type: ignore[import-not-found]


client = TestClient(app)


def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_ready() -> None:
    response = client.get("/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_register_and_me() -> None:
    register_response = client.post(
        "/api/v1/auth/register",
        json={
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
    assert me_response.json()["email"] == "user1@example.com"


def test_refresh_and_logout_flow() -> None:
    register_response = client.post(
        "/api/v1/auth/register",
        json={
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


def test_login_with_wrong_password_returns_401() -> None:
    register_response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "user3@example.com",
            "password": "MyStrongPass123",
            "role": "client",
        },
    )
    assert register_response.status_code == 201

    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "user3@example.com",
            "password": "WrongPass123",
        },
    )
    assert login_response.status_code == 401


def test_register_duplicate_email_returns_409() -> None:
    payload = {
        "email": "dup@example.com",
        "password": "MyStrongPass123",
        "role": "client",
    }
    first_response = client.post("/api/v1/auth/register", json=payload)
    assert first_response.status_code == 201

    second_response = client.post("/api/v1/auth/register", json=payload)
    assert second_response.status_code == 409


def test_me_without_bearer_token_returns_401() -> None:
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401


def test_refresh_with_invalid_token_returns_401() -> None:
    response = client.post("/api/v1/auth/refresh", json={"refresh_token": "not-a-valid-token"})
    assert response.status_code == 401


def test_check_with_valid_access_token_returns_user() -> None:
    register_response = client.post(
        "/api/v1/auth/register",
        json={
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
    assert check_response.json()["email"] == "check@example.com"


def test_check_with_invalid_access_token_returns_401() -> None:
    check_response = client.post("/api/v1/auth/check", json={"access_token": "bad-token"})
    assert check_response.status_code == 401