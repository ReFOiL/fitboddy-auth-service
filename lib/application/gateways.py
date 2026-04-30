from __future__ import annotations

import httpx

from application.errors import IntegrationError


class MarketplaceGateway:
    def __init__(self, http_client: httpx.Client, tenant_service_url: str) -> None:
        self._http_client = http_client
        self._tenant_service_url = tenant_service_url.rstrip("/")

    def upsert_discovery_profile(self, user_id: str, role: str) -> None:
        payload = {
            "role": role,
            "is_visible": True,
            "looking_for_trainer": role == "client",
        }
        try:
            response = self._http_client.put(
                f"{self._tenant_service_url}/api/v1/marketplace/users/{user_id}/profile",
                json=payload,
            )
        except httpx.HTTPError as exc:
            raise IntegrationError("marketplace service is unavailable") from exc

        if response.status_code >= 500:
            raise IntegrationError("marketplace service returned server error")
        if response.status_code not in {200, 201}:
            raise IntegrationError("marketplace profile sync failed")
