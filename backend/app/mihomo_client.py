"""Mihomo REST API client (external controller).

Thin sync wrapper around the Clash-compatible API, built on ``httpx``.
Every failure raises :class:`MihomoError`, which distinguishes
connection errors (mihomo unreachable — ``connection_error`` is True,
``status`` is None) from HTTP errors (``status`` carries the code).

The API base URL is configurable because deployment differs by setup:
binary + systemd on the N1 talks to ``http://127.0.0.1:9090``,
while the later Docker Compose alternative uses the ``mihomo``
service name (``http://mihomo:9090``).
"""

from __future__ import annotations

import json
import urllib.parse

import httpx

DEFAULT_TIMEOUT = 10.0


class MihomoError(Exception):
    """Any mihomo API failure.

    ``connection_error=True`` means the request never reached mihomo
    (down / refused / timeout); otherwise ``status`` holds the HTTP
    status code and the message carries the API's error text.
    """

    def __init__(
        self,
        message: str,
        status: int | None = None,
        connection_error: bool = False,
    ):
        super().__init__(message)
        self.message = message
        self.status = status
        self.connection_error = connection_error


class MihomoClient:
    """Thin wrapper around the mihomo external-controller API."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:9090",
        secret: str = "",
        timeout: float = DEFAULT_TIMEOUT,
    ):
        self.base_url = base_url.rstrip("/")
        self.secret = secret
        self.timeout = timeout

    @property
    def headers(self) -> dict[str, str]:
        if not self.secret:
            return {}
        return {"Authorization": f"Bearer {self.secret}"}

    def url(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"

    # -- low-level ------------------------------------------------------
    def _request(self, method: str, path: str, **kwargs: object) -> httpx.Response:
        # trust_env=False: the controller is a LAN/local address and must
        # never go through an HTTP(S)_PROXY from the environment.
        try:
            with httpx.Client(
                headers=self.headers, timeout=self.timeout, trust_env=False
            ) as client:
                response = client.request(method, self.url(path), **kwargs)
        except httpx.ConnectError as exc:
            raise MihomoError(
                f"cannot reach mihomo at {self.base_url}: {exc}",
                connection_error=True,
            ) from exc
        except httpx.TimeoutException as exc:
            raise MihomoError(
                f"mihomo request timed out after {self.timeout}s: "
                f"{method} {path}",
                connection_error=True,
            ) from exc
        except httpx.HTTPError as exc:
            raise MihomoError(
                f"mihomo request failed: {exc}", connection_error=True
            ) from exc
        except ValueError as exc:
            # httpx.InvalidURL is a ValueError, not an HTTPError: a
            # malformed base URL is a configuration error, not a crash.
            raise MihomoError(
                f"invalid mihomo base URL {self.base_url!r}: {exc}",
                connection_error=True,
            ) from exc
        if response.status_code >= 400:
            detail = response.text.strip()[:300] or response.reason_phrase
            raise MihomoError(
                f"mihomo API error ({method} {path}): {detail}",
                status=response.status_code,
            )
        return response

    def _get_json(self, path: str, **kwargs: object) -> dict:
        response = self._request("GET", path, **kwargs)
        try:
            data = response.json()
        except ValueError as exc:
            raise MihomoError(
                f"mihomo returned non-JSON for GET {path}",
                status=response.status_code,
            ) from exc
        if not isinstance(data, dict):
            raise MihomoError(
                f"mihomo returned unexpected JSON for GET {path}",
                status=response.status_code,
            )
        return data

    # -- API ------------------------------------------------------------
    def get_version(self) -> dict:
        """GET /version — core version info (``{"version": ...}``)."""
        return self._get_json("/version")

    def reload_config(self, force: bool = True) -> None:
        """PUT /configs — hot reload the on-disk config file.

        An empty JSON body reloads the config file mihomo was started
        with; ``force=true`` applies it even if only comments changed.
        """
        params = {"force": "true" if force else "false"}
        self._request("PUT", "/configs", params=params, json={})

    def get_proxies(self) -> dict:
        """GET /proxies — all proxies and proxy groups."""
        return self._get_json("/proxies")

    def get_proxy_group(self, name: str) -> dict:
        """GET /proxies/<group> — one group's live state.

        The response carries ``now`` (the proxy currently selected by
        the group's policy), ``all`` (member proxies) and ``type``.
        """
        encoded = urllib.parse.quote(name, safe="")
        return self._get_json(f"/proxies/{encoded}")

    def test_delay(self, proxy: str, url: str, timeout: int = 5) -> int:
        """GET /proxies/<proxy>/delay — latency probe, returns ms.

        Raises :class:`MihomoError` if mihomo reports a timeout or an
        error for the proxy (the API answers 408 when the probe fails).
        """
        encoded = urllib.parse.quote(proxy, safe="")
        data = self._get_json(
            f"/proxies/{encoded}/delay",
            params={"timeout": str(timeout * 1000), "url": url},
        )
        delay = data.get("delay")
        if not isinstance(delay, int):
            raise MihomoError(
                f"mihomo returned no delay for proxy {proxy!r}",
                status=200,
            )
        return delay

    def get_connections(self) -> dict:
        """GET /connections — active connections + totals."""
        return self._get_json("/connections")

    def get_traffic(self, timeout: float = 5.0) -> dict:
        """Read one sample from the GET /traffic stream (``up``/``down``).

        ``/traffic`` is a streaming endpoint, so this opens the stream,
        reads the first JSON line (``{"up": <B/s>, "down": <B/s>}``),
        then closes it. Raises :class:`MihomoError` on failure.
        """
        try:
            with httpx.Client(
                headers=self.headers, timeout=timeout, trust_env=False
            ) as client:
                with client.stream("GET", self.url("/traffic")) as response:
                    if response.status_code >= 400:
                        raise MihomoError(
                            "mihomo API error (GET /traffic): "
                            f"{response.status_code}",
                            status=response.status_code,
                        )
                    for line in response.iter_lines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                        except ValueError as exc:
                            raise MihomoError(
                                "mihomo /traffic returned non-JSON data"
                            ) from exc
                        if not isinstance(data, dict):
                            raise MihomoError(
                                "mihomo /traffic returned unexpected data"
                            )
                        return {
                            "up": int(data.get("up", 0)),
                            "down": int(data.get("down", 0)),
                        }
        except MihomoError:
            raise
        except httpx.ConnectError as exc:
            raise MihomoError(
                f"cannot reach mihomo at {self.base_url}: {exc}",
                connection_error=True,
            ) from exc
        except httpx.TimeoutException as exc:
            raise MihomoError(
                f"mihomo /traffic timed out after {timeout}s",
                connection_error=True,
            ) from exc
        except httpx.HTTPError as exc:
            raise MihomoError(
                f"mihomo /traffic request failed: {exc}",
                connection_error=True,
            ) from exc
        except ValueError as exc:
            raise MihomoError(
                f"invalid mihomo base URL {self.base_url!r}: {exc}",
                connection_error=True,
            ) from exc
        raise MihomoError("mihomo /traffic stream closed without data")
