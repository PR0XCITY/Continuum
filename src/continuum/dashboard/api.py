"""HTTP client for the connector API, used by the dashboard.

Responsibility: the dashboard's only way to read or change anything.
It never opens the SQLite database, the Chroma store or the capture
layer; every call goes to the connector over HTTP with the bearer
token. Failures are raised as ApiError with a message written for the
person looking at the dashboard, not a stack trace.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx

DEFAULT_TIMEOUT_SECONDS = 10.0
QUERY_TIMEOUT_SECONDS = 180.0


class ApiError(RuntimeError):
    """A connector call failed; str(error) is safe to show in the UI."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class ConnectorClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.base_url = base_url
        self._client = httpx.Client(
            base_url=base_url,
            timeout=timeout,
            headers={"Authorization": f"Bearer {token}"},
            transport=transport,
        )

    def close(self) -> None:
        self._client.close()

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            response = self._client.request(method, path, **kwargs)
        except httpx.ConnectError as error:
            raise ApiError(
                f"Cannot reach the connector at {self.base_url}. Is it running?"
            ) from error
        except httpx.TimeoutException as error:
            raise ApiError(f"The connector did not answer {method} {path} in time.") from error
        except httpx.HTTPError as error:
            raise ApiError(f"Request to the connector failed: {error}") from error

        if response.status_code == 401:
            raise ApiError(
                "The connector rejected the API token. Check CONTINUUM_API_TOKEN in .env.",
                status_code=401,
            )
        if response.status_code == 429:
            raise ApiError(
                "The connector is rate limiting requests. Wait a moment.", status_code=429
            )
        if response.status_code >= 400:
            try:
                detail = response.json().get("detail", response.text)
            except ValueError:
                detail = response.text
            raise ApiError(
                f"{method} {path} failed with HTTP {response.status_code}: {detail}",
                status_code=response.status_code,
            )
        return response.json()

    # --- reads -----------------------------------------------------------------

    def health(self) -> dict:
        return self._request("GET", "/health")

    def runtime(self) -> dict:
        return self._request("GET", "/runtime")

    def live(self) -> list[dict]:
        return self._request("GET", "/live")

    def incidents(self, params: dict[str, Any] | None = None) -> dict:
        return self._request("GET", "/incidents", params=params or {})

    def incident(self, incident_id: str) -> dict:
        return self._request("GET", f"/incidents/{incident_id}")

    def stats(self) -> dict:
        return self._request("GET", "/stats")

    def calibration(self) -> dict:
        return self._request("GET", "/calibration")

    def get_settings(self) -> dict:
        return self._request("GET", "/settings")

    # --- actions ---------------------------------------------------------------

    def unblock(self, device_id: str) -> dict:
        # Device ids are Windows instance ids such as HID\VID_046D&PID_C31C\7&1A2B&0&0000.
        return self._request("POST", f"/devices/{quote(device_id, safe='')}/unblock")

    def query(self, question: str) -> dict:
        return self._request(
            "POST", "/query", json={"question": question}, timeout=QUERY_TIMEOUT_SECONDS
        )

    def put_settings(self, settings: dict[str, Any]) -> dict:
        return self._request("PUT", "/settings", json=settings)
