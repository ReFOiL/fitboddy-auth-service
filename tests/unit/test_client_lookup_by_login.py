from fastapi.testclient import TestClient
import pytest

from application.commands import BootstrapPlatformAdminCommand
from application.config import Settings
from application.runtime import AuthApplicationRuntime
from presentation.http.main import app  # type: ignore[import-not-found]


LOOKUP_PATH = "/api/v1/auth/clients/by-login"
PASSWORD = "MyStrongPass123"
CLIENT_NOT_FOUND = {"detail": "Client not found."}
INVALID_LOGIN = {"detail": "Unsupported login format. Use 3-32 chars: a-z, 0-9, _, -, ."}


@pytest.fixture()
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


def _register(client: TestClient, *, login: str, email: str, role: str) -> dict:
    response = client.post(
        "/api/v1/auth/register",
        json={"login": login, "email": email, "password": PASSWORD, "role": role},
    )
    assert response.status_code == 201
    return response.json()


def _bearer(access_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}"}


def _admin_token(client: TestClient) -> str:
    runtime = AuthApplicationRuntime(Settings())
    with runtime.auth_service_scope() as auth_service:
        auth_service.bootstrap_platform_admin(
            BootstrapPlatformAdminCommand(
                login="lookup_admin",
                email="lookup-admin@example.com",
                password=PASSWORD,
            )
        )
    runtime.shutdown()
    login_response = client.post(
        "/api/v1/auth/login",
        json={"email_or_login": "lookup_admin", "password": PASSWORD},
    )
    assert login_response.status_code == 200
    assert login_response.json()["user"]["role"] == "platform_admin"
    return login_response.json()["tokens"]["access_token"]


def test_trainer_lookup_returns_client_without_email(client: TestClient) -> None:
    trainer = _register(client, login="lookup_trainer", email="lookup-trainer@example.com", role="trainer")
    target = _register(client, login="lookup_client", email="lookup-client@example.com", role="client")
    trainer_token = trainer["tokens"]["access_token"]

    response = client.get(
        LOOKUP_PATH,
        headers=_bearer(trainer_token),
        params={"login": "  LookUp_Client \n"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body == {
        "user_id": target["user"]["user_id"],
        "login": "lookup_client",
        "role": "client",
    }
    assert set(body) == {"user_id", "login", "role"}
    assert "lookup-client@example.com" not in response.text
    assert "email" not in body

    prefix = client.get(LOOKUP_PATH, headers=_bearer(trainer_token), params={"login": "lookup_clien"})
    assert prefix.status_code == 404
    assert prefix.json() == CLIENT_NOT_FOUND


def test_platform_admin_can_lookup_client(client: TestClient) -> None:
    target = _register(client, login="lookup_admin_target", email="lookup-admin-target@example.com", role="client")
    admin_token = _admin_token(client)

    response = client.get(
        LOOKUP_PATH,
        headers=_bearer(admin_token),
        params={"login": "LOOKUP_ADMIN_TARGET"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "user_id": target["user"]["user_id"],
        "login": "lookup_admin_target",
        "role": "client",
    }
    assert "lookup-admin-target@example.com" not in response.text


def test_lookup_requires_trainer_or_platform_admin(client: TestClient) -> None:
    caller = _register(client, login="lookup_caller_client", email="lookup-caller@example.com", role="client")
    _register(client, login="lookup_hidden_client", email="lookup-hidden@example.com", role="client")
    client_token = caller["tokens"]["access_token"]

    forbidden = client.get(LOOKUP_PATH, headers=_bearer(client_token), params={"login": "lookup_hidden_client"})
    assert forbidden.status_code == 403
    assert forbidden.json() == {"detail": "trainer or platform_admin role required"}
    assert "lookup-hidden@example.com" not in forbidden.text

    missing = client.get(LOOKUP_PATH, params={"login": "lookup_hidden_client"})
    assert missing.status_code == 401
    assert missing.json() == {"detail": "Missing Bearer token."}

    invalid = client.get(
        LOOKUP_PATH,
        headers={"Authorization": "Bearer not-a-token"},
        params={"login": "lookup_hidden_client"},
    )
    assert invalid.status_code == 401

    # Без токена и с чужой ролью формат логина не раскрываем: сначала аутентификация и роль.
    anonymous_invalid = client.get(LOOKUP_PATH, params={"login": "bad login"})
    assert anonymous_invalid.status_code == 401
    client_invalid = client.get(LOOKUP_PATH, headers=_bearer(client_token), params={"login": "x"})
    assert client_invalid.status_code == 403


def test_lookup_not_found_is_identical_for_missing_inactive_and_non_client(client: TestClient) -> None:
    trainer = _register(client, login="lookup_seeker", email="lookup-seeker@example.com", role="trainer")
    inactive_client = _register(
        client,
        login="lookup_inactive",
        email="lookup-inactive@example.com",
        role="client",
    )
    _register(client, login="lookup_other_trainer", email="lookup-other-trainer@example.com", role="trainer")
    admin_token = _admin_token(client)
    trainer_token = trainer["tokens"]["access_token"]

    deactivated = client.patch(
        f"/api/v1/admin/users/{inactive_client['user']['user_id']}",
        headers=_bearer(admin_token),
        json={"is_active": False},
    )
    assert deactivated.status_code == 200
    assert deactivated.json()["is_active"] is False

    headers = _bearer(trainer_token)
    missing = client.get(LOOKUP_PATH, headers=headers, params={"login": "lookup_nobody"})
    inactive = client.get(LOOKUP_PATH, headers=headers, params={"login": "lookup_inactive"})
    other_trainer = client.get(LOOKUP_PATH, headers=headers, params={"login": "lookup_other_trainer"})
    admin_target = client.get(LOOKUP_PATH, headers=headers, params={"login": "lookup_admin"})

    assert missing.status_code == inactive.status_code == other_trainer.status_code == admin_target.status_code == 404
    assert missing.content == inactive.content == other_trainer.content == admin_target.content
    assert missing.json() == CLIENT_NOT_FOUND
    for response in (missing, inactive, other_trainer, admin_target):
        assert "email" not in response.text
        assert "@example.com" not in response.text


def test_lookup_rejects_invalid_login(client: TestClient) -> None:
    trainer = _register(client, login="lookup_format_trainer", email="lookup-format@example.com", role="trainer")
    headers = _bearer(trainer["tokens"]["access_token"])

    missing_param = client.get(LOOKUP_PATH, headers=headers)
    assert missing_param.status_code == 422

    for login in ("ab", "   ", "bad login", "client@example.com", "a" * 33, "логин123", "client login"):
        response = client.get(LOOKUP_PATH, headers=headers, params={"login": login})
        assert response.status_code == 422
        assert response.json() == INVALID_LOGIN


def test_lookup_openapi_contract_excludes_email(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    operation = schema["paths"]["/api/v1/auth/clients/by-login"]["get"]
    login_param = next(item for item in operation["parameters"] if item["name"] == "login")
    assert login_param["in"] == "query"
    assert login_param["required"] is True

    response_schema = schema["components"]["schemas"]["ClientLookupResponse"]
    assert set(response_schema["properties"]) == {"user_id", "login", "role"}
    assert "email" not in response_schema["properties"]
    role_schema = response_schema["properties"]["role"]
    assert role_schema.get("const") == "client" or role_schema.get("enum") == ["client"]
    assert "404" in operation["responses"]
    assert "422" in operation["responses"]
    assert "403" in operation["responses"]
