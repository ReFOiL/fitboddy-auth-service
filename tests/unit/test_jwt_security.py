import base64
import json
from datetime import UTC, datetime

import jwt
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from application.config import (
    INSECURE_JWT_SECRET,
    MAX_ACCESS_TOKEN_LIFETIME_SECONDS,
    MAX_ACCESS_TOKEN_TTL_MINUTES,
    MAX_REFRESH_TOKEN_TTL_MINUTES,
    MAX_TOKEN_LIFETIME_SECONDS,
    MIN_JWT_SECRET_BYTES,
    Settings,
)
from application.security import JwtService, TokenError
from presentation.http.main import app


VALID_SECRET = "a" * MIN_JWT_SECRET_BYTES
SHIPPED_DEFAULT_SECRET = "auth_service_dev_secret_change_me"


def _now() -> int:
    return int(datetime.now(UTC).timestamp())


def _service(secret: str = VALID_SECRET) -> JwtService:
    return JwtService(secret=secret, algorithm="HS256")


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _token(payload: dict, *, secret: str = VALID_SECRET, algorithm: str = "HS256") -> str:
    return jwt.encode(payload, secret, algorithm=algorithm)


def _unsigned(payload: dict, algorithm: str) -> str:
    header = _b64(json.dumps({"alg": algorithm, "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    return f"{header}.{body}."


def test_shipped_default_is_long_enough_that_length_alone_does_not_reject_it() -> None:
    assert INSECURE_JWT_SECRET == SHIPPED_DEFAULT_SECRET
    assert len(SHIPPED_DEFAULT_SECRET.encode("utf-8")) >= MIN_JWT_SECRET_BYTES


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("JWT_SECRET", None),
        ("JWT_SECRET", SHIPPED_DEFAULT_SECRET),
        ("JWT_SECRET", "x" * (MIN_JWT_SECRET_BYTES - 1)),
        ("JWT_SECRET", ""),
        ("JWT_ALGORITHM", "RS256"),
        ("JWT_ALGORITHM", "none"),
        ("JWT_ALGORITHM", "hs256"),
        ("ACCESS_TOKEN_TTL_MINUTES", "0"),
        ("ACCESS_TOKEN_TTL_MINUTES", str(MAX_ACCESS_TOKEN_TTL_MINUTES + 1)),
        ("REFRESH_TOKEN_TTL_MINUTES", "4"),
        ("REFRESH_TOKEN_TTL_MINUTES", str(MAX_REFRESH_TOKEN_TTL_MINUTES + 1)),
    ],
)
def test_settings_reject_unsafe_jwt_config(monkeypatch: pytest.MonkeyPatch, name: str, value: str | None) -> None:
    if value is None:
        monkeypatch.delenv(name, raising=False)
    else:
        monkeypatch.setenv(name, value)

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_settings_keep_ttl_defaults_and_accept_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ACCESS_TOKEN_TTL_MINUTES", raising=False)
    monkeypatch.delenv("REFRESH_TOKEN_TTL_MINUTES", raising=False)
    monkeypatch.delenv("JWT_ALGORITHM", raising=False)
    monkeypatch.setenv("JWT_SECRET", "я" * 16)

    settings = Settings(_env_file=None)

    assert len(settings.jwt_secret.encode("utf-8")) == MIN_JWT_SECRET_BYTES
    assert settings.jwt_algorithm == "HS256"
    assert settings.access_token_ttl_minutes == 15
    assert settings.refresh_token_ttl_minutes == 10080

    monkeypatch.setenv("JWT_ALGORITHM", "HS256")
    monkeypatch.setenv("ACCESS_TOKEN_TTL_MINUTES", str(MAX_ACCESS_TOKEN_TTL_MINUTES))
    monkeypatch.setenv("REFRESH_TOKEN_TTL_MINUTES", str(MAX_REFRESH_TOKEN_TTL_MINUTES))
    bounded = Settings(_env_file=None)
    assert bounded.access_token_ttl_minutes == MAX_ACCESS_TOKEN_TTL_MINUTES
    assert bounded.refresh_token_ttl_minutes == MAX_REFRESH_TOKEN_TTL_MINUTES


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("JWT_SECRET", None),
        ("JWT_SECRET", SHIPPED_DEFAULT_SECRET),
        ("JWT_SECRET", "x" * (MIN_JWT_SECRET_BYTES - 1)),
        ("JWT_ALGORITHM", "RS256"),
        ("ACCESS_TOKEN_TTL_MINUTES", str(MAX_ACCESS_TOKEN_TTL_MINUTES + 1)),
        ("REFRESH_TOKEN_TTL_MINUTES", str(MAX_REFRESH_TOKEN_TTL_MINUTES + 1)),
    ],
)
def test_app_refuses_to_start_with_unsafe_jwt_config(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    value: str | None,
) -> None:
    if value is None:
        monkeypatch.delenv(name, raising=False)
    else:
        monkeypatch.setenv(name, value)

    with pytest.raises(ValidationError):
        with TestClient(app):
            pass


def test_jwt_service_rejects_unpinned_algorithm() -> None:
    with pytest.raises(ValueError):
        JwtService(secret=VALID_SECRET, algorithm="RS256")


def test_issued_tokens_satisfy_claim_requirements() -> None:
    service = _service()
    pair = service.build_token_pair(
        user_id="user-1",
        tenant_id="marketplace",
        role="client",
        access_ttl_minutes=MAX_ACCESS_TOKEN_TTL_MINUTES,
        refresh_ttl_minutes=MAX_REFRESH_TOKEN_TTL_MINUTES,
    )

    access = service.verify_token(pair.access_token)
    refresh = service.verify_token(pair.refresh_token)

    assert access["sub"] == "user-1"
    assert access["type"] == "access"
    assert refresh["sub"] == "user-1"
    assert refresh["type"] == "refresh"


@pytest.mark.parametrize("claim", ["exp", "iat", "sub"])
def test_verify_token_requires_claim(claim: str) -> None:
    now = _now()
    payload = {"sub": "user-1", "iat": now, "exp": now + 60, "type": "access"}
    del payload[claim]

    with pytest.raises(TokenError):
        _service().verify_token(_token(payload))


def test_verify_token_rejects_non_string_subject() -> None:
    now = _now()
    payload = {"sub": 123, "iat": now, "exp": now + 60, "type": "access"}

    with pytest.raises(TokenError):
        _service().verify_token(_token(payload))


def test_verify_token_rejects_expired_token_and_future_iat() -> None:
    now = _now()
    expired = {"sub": "user-1", "iat": now - 120, "exp": now - 60, "type": "access"}
    future = {"sub": "user-1", "iat": now + 3600, "exp": now + 7200, "type": "access"}

    with pytest.raises(TokenError):
        _service().verify_token(_token(expired))
    with pytest.raises(TokenError):
        _service().verify_token(_token(future))


def test_verify_token_enforces_lifetime_caps() -> None:
    now = _now()
    service = _service()

    access_at_cap = {
        "sub": "user-1",
        "iat": now,
        "exp": now + MAX_ACCESS_TOKEN_LIFETIME_SECONDS,
        "type": "access",
    }
    access_over_cap = {
        "sub": "user-1",
        "iat": now,
        "exp": now + MAX_ACCESS_TOKEN_LIFETIME_SECONDS + 1,
        "type": "access",
    }
    refresh_at_cap = {
        "sub": "user-1",
        "iat": now,
        "exp": now + MAX_TOKEN_LIFETIME_SECONDS,
        "type": "refresh",
    }
    refresh_over_cap = {
        "sub": "user-1",
        "iat": now,
        "exp": now + MAX_TOKEN_LIFETIME_SECONDS + 1,
        "type": "refresh",
    }

    assert service.verify_token(_token(access_at_cap))["type"] == "access"
    assert service.verify_token(_token(refresh_at_cap))["type"] == "refresh"
    with pytest.raises(TokenError):
        service.verify_token(_token(access_over_cap))
    with pytest.raises(TokenError):
        service.verify_token(_token(refresh_over_cap))


def test_verify_token_rejects_other_algorithms() -> None:
    now = _now()
    payload = {"sub": "user-1", "iat": now, "exp": now + 60, "type": "access"}
    hs512_secret = "b" * 64

    with pytest.raises(TokenError):
        _service().verify_token(_token(payload, secret=hs512_secret, algorithm="HS512"))
    with pytest.raises(TokenError):
        _service().verify_token(_unsigned(payload, "none"))
