"""Thin IBM Security Verify SaaS REST client (SCIM 2.0 + v1.0 management API).

Auth model: OAuth2 client-credentials with an API Client's client_id +
client_secret, scoped to one tenant hostname.
"""
from __future__ import annotations

import time
from typing import Any

import httpx


class VerifyError(RuntimeError):
    """A safe provider-facing error; never includes credentials."""

    def __init__(self, message: str, retryable: bool = False):
        super().__init__(message)
        self.retryable = retryable


class VerifyClient:
    """REST client for IBM Security Verify, scoped to one tenant."""

    def __init__(
        self,
        tenant_hostname: str,
        client_id: str,
        client_secret: str,
        *,
        timeout: float = 30.0,
    ):
        host = (tenant_hostname or "").strip().rstrip("/")
        host = host.replace("https://", "").replace("http://", "")
        if not host:
            raise VerifyError("Tenant hostname is required, e.g. 'mycompany.verify.ibm.com'.")
        if not client_id or not client_secret:
            raise VerifyError("Client ID and Client Secret are required.")
        self.tenant_hostname = host
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = f"https://{host}"
        self.token_url = f"{self.base_url}/v1.0/endpoint/default/token"
        self.timeout = timeout
        self._access_token = ""
        self._token_expiry = 0.0

    async def _ensure_token(self) -> str:
        if self._access_token and time.time() < self._token_expiry - 30:
            return self._access_token
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                resp = await client.post(
                    self.token_url,
                    data={
                        "grant_type": "client_credentials",
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            except httpx.RequestError as exc:
                raise VerifyError(f"Could not reach {self.tenant_hostname}: {exc}", retryable=True) from exc
        if resp.status_code == 401:
            raise VerifyError("Authentication failed. Check the Client ID and Client Secret.")
        if resp.status_code >= 400:
            raise VerifyError(f"Token request failed ({resp.status_code}). Check the tenant hostname and credentials.")
        data = resp.json()
        token = data.get("access_token", "")
        if not token:
            raise VerifyError("Token endpoint did not return an access token.")
        self._access_token = token
        self._token_expiry = time.time() + float(data.get("expires_in", 3600))
        return token

    async def request(
        self, method: str, path: str, params: dict | None = None, json_body: dict | None = None,
    ) -> tuple[Any, dict]:
        token = await self._ensure_token()
        url = f"{self.base_url}{path}"
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                resp = await client.request(method, url, params=params, json=json_body, headers=headers)
            except httpx.RequestError as exc:
                raise VerifyError(f"Could not reach {self.tenant_hostname}: {exc}", retryable=True) from exc
        if resp.status_code == 401:
            raise VerifyError("Authentication expired or invalid. Reconnect the tenant.")
        if resp.status_code == 403:
            raise VerifyError("Access client lacks the entitlement required for this action.")
        if resp.status_code == 404:
            raise VerifyError("Not found.")
        if resp.status_code == 429:
            raise VerifyError("Rate limited by IBM Security Verify. Try again shortly.", retryable=True)
        if resp.status_code >= 500:
            raise VerifyError("IBM Security Verify reported a server error.", retryable=True)
        if resp.status_code >= 400:
            raise VerifyError(f"Request failed ({resp.status_code}): {resp.text[:300]}")
        try:
            data = resp.json() if resp.content else {}
        except ValueError:
            data = {}
        return data, dict(resp.headers)

    async def verify_connection(self) -> dict:
        data, _ = await self.request("GET", "/v2.0/Users", params={"count": 1})
        return data
