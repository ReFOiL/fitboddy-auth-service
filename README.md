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
- `POST /api/v1/auth/check`

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