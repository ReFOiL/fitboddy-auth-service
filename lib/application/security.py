from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from application.config import (
    MAX_ACCESS_TOKEN_LIFETIME_SECONDS,
    MAX_TOKEN_LIFETIME_SECONDS,
    PINNED_JWT_ALGORITHM,
)


class TokenError(Exception):
    pass


@dataclass(frozen=True)
class TokenPairData:
    access_token: str
    refresh_token: str
    refresh_jti: str
    refresh_expires_at: datetime


class PasswordService:
    def __init__(self) -> None:
        self._hasher = PasswordHasher()

    def hash(self, raw_password: str) -> str:
        return self._hasher.hash(raw_password)

    def verify(self, raw_password: str, password_hash: str) -> bool:
        try:
            return self._hasher.verify(password_hash, raw_password)
        except VerifyMismatchError:
            return False


class JwtService:
    def __init__(self, secret: str, algorithm: str) -> None:
        if algorithm != PINNED_JWT_ALGORITHM:
            raise ValueError("JWT algorithm must be HS256 until asymmetric signing exists.")
        self._secret = secret

    def build_token_pair(
        self,
        *,
        user_id: str,
        tenant_id: str,
        role: str,
        access_ttl_minutes: int,
        refresh_ttl_minutes: int,
    ) -> TokenPairData:
        now = datetime.now(UTC)
        access_exp = now + timedelta(minutes=access_ttl_minutes)
        refresh_exp = now + timedelta(minutes=refresh_ttl_minutes)
        refresh_jti = str(uuid4())

        access_payload = {
            "sub": user_id,
            "tenant_id": tenant_id,
            "role": role,
            "type": "access",
            "iat": int(now.timestamp()),
            "exp": int(access_exp.timestamp()),
        }
        refresh_payload = {
            "sub": user_id,
            "tenant_id": tenant_id,
            "role": role,
            "type": "refresh",
            "jti": refresh_jti,
            "iat": int(now.timestamp()),
            "exp": int(refresh_exp.timestamp()),
        }
        return TokenPairData(
            access_token=jwt.encode(access_payload, self._secret, algorithm=PINNED_JWT_ALGORITHM),
            refresh_token=jwt.encode(refresh_payload, self._secret, algorithm=PINNED_JWT_ALGORITHM),
            refresh_jti=refresh_jti,
            refresh_expires_at=refresh_exp,
        )

    def verify_token(self, token: str) -> dict:
        try:
            payload = jwt.decode(
                token,
                self._secret,
                algorithms=[PINNED_JWT_ALGORITHM],
                options={
                    "require": ["exp", "iat", "sub"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_sub": True,
                    "enforce_minimum_key_length": True,
                },
            )
        except jwt.PyJWTError as exc:
            raise TokenError("Invalid token.") from exc
        self._reject_excessive_lifetime(payload)
        return payload

    def _reject_excessive_lifetime(self, payload: dict) -> None:
        issued_at = payload["iat"]
        expires_at = payload["exp"]
        # bool — подкласс int, его нельзя принимать как unix-время.
        if type(issued_at) is not int or type(expires_at) is not int:
            raise TokenError("Invalid token.")
        lifetime = expires_at - issued_at
        if payload.get("type") == "access":
            limit = MAX_ACCESS_TOKEN_LIFETIME_SECONDS
        else:
            limit = MAX_TOKEN_LIFETIME_SECONDS
        if lifetime > limit:
            raise TokenError("Invalid token.")
