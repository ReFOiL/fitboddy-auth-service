# auth-service

Auth service for Fitboddy Platform MVP.

## Stack

- FastAPI + Poetry
- SQLAlchemy + PostgreSQL
- JWT access/refresh tokens
- Argon2id password hashing
- Alembic migrations

## Endpoints

- `GET /health`
- `GET /ready`
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/auth/logout`
- `GET /api/v1/auth/me`
- `GET /api/v1/auth/clients/by-login?login={login}` (bearer; `trainer` or `platform_admin`. Exact login after trim and lowercase, `^[a-z0-9_.-]{3,32}$`. `200`: `user_id`, `login`, `role=client` — no email. One `404` for missing, inactive, or non-client. `422` if the login is invalid. `403` for other roles.)
- `POST /api/v1/auth/check`
- `POST /api/v1/auth/internal/summaries` (internal: `user_ids` -> `login`)

## Environment

- `DATABASE_URL` (required in k8s via secret)
- `JWT_SECRET` (required in k8s for secure setup)
- `JWT_ALGORITHM` (default: `HS256`)
- `ACCESS_TOKEN_TTL_MINUTES` (default: `15`)
- `REFRESH_TOKEN_TTL_MINUTES` (default: `10080`)
- `TENANT_SERVICE_URL` (default: `http://tenant-service`)
- `HTTP_TIMEOUT_SECONDS` (default: `5`)
- `MARKETPLACE_PROFILE_SYNC_ENABLED` (default: `true`)
- `ALEMBIC_INI_PATH` (default: `alembic.ini`)

## Migrations

```bash
poetry run alembic upgrade head
```

## Local run

```bash
poetry install
poetry run uvicorn --app-dir lib presentation.http.main:app --reload --port 8000
```

## Tests

```bash
poetry run pytest tests/unit
```