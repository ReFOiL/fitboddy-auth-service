from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


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
        self._secret = secret
        self._algorithm = algorithm

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
            access_token=jwt.encode(access_payload, self._secret, algorithm=self._algorithm),
            refresh_token=jwt.encode(refresh_payload, self._secret, algorithm=self._algorithm),
            refresh_jti=refresh_jti,
            refresh_expires_at=refresh_exp,
        )

    def verify_token(self, token: str) -> dict:
        try:
            return jwt.decode(token, self._secret, algorithms=[self._algorithm])
        except jwt.PyJWTError as exc:
            raise TokenError("Invalid token.") from exc
