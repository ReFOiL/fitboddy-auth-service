from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class User:
    user_id: str
    tenant_id: str
    login: str
    email: str
    role: str
    is_active: bool
    created_at: datetime


@dataclass(frozen=True)
class UserSummary:
    user_id: str
    login: str