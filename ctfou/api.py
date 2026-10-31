"""Read-only CTFd client. Never makes challenge submissions."""
from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler

BASE_URL = "https://ctfou.saikolabs.in"
MAX_FILE_SIZE = 4 * 1024 * 1024


class ApiError(Exception):
    """Safe error; never includes URLs or credentials."""


class _BlockRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ApiError("Redirect rejected; attachment must stay on the CTFOU origin")


class CTFdClient:
    def __init__(self, token: str, base_url: str = BASE_URL):
        self.token = token.strip()
        origin = urlsplit(base_url)
        if origin.scheme != "https" or not origin.hostname:
            raise ValueError("CTF site must have an HTTPS URL")
        self.base_url = base_url.rstrip("/")
        self.origin = (origin.scheme, origin.netloc)
        self._opener = build_opener(_BlockRedirect())

    def _get(self, relative: str, max_bytes: int) -> bytes:
        parsed = urlsplit(relative)
        if parsed.scheme or parsed.netloc or relative.startswith("//"):
            raise ApiError("Only same-origin relative paths are allowed")
        url = urljoin(self.base_url + "/", relative.lstrip("/"))
        checked = urlsplit(url)
        if (checked.scheme, checked.netloc) != self.origin:
            raise ApiError("Cross-origin request blocked")
        headers = {"Accept": "application/json", "User-Agent": "CTFOU-OptIn-Solver/1.0"}
        if self.token:
            headers["Authorization"] = f"Token {self.token}"
        request = Request(url, headers=headers, method="GET")
        try:
            with self._opener.open(request, timeout=16) as response:
                declared = response.headers.get("Content-Length", "")
                if declared.isdigit() and int(declared) > max_bytes:
                    raise ApiError("Response exceeded size limit")
                content = response.read(max_bytes + 1)
                if len(content) > max_bytes:
                    raise ApiError("Response exceeded size limit")
                return content
        except HTTPError as exc:
            raise ApiError(f"CTFd responded HTTP {exc.code}") from None
        except (URLError, TimeoutError, OSError) as exc:
            raise ApiError(f"CTFd connection error: {type(exc).__name__}") from None

    def _json(self, path: str):
        try:
            response = json.loads(self._get(path, 1024 * 1024))
            if response.get("success") is not True or "data" not in response:
                raise ApiError("CTFd returned a non-success API response")
            return response["data"]
        except (ValueError, TypeError) as exc:
            raise ApiError(f"Invalid API JSON: {type(exc).__name__}") from None

    def challenges(self) -> list[dict]:
        result = self._json("/api/v1/challenges")
        if not isinstance(result, list):
            raise ApiError("Invalid challenge list")
        return result

    def challenge(self, challenge_id: int | str) -> dict:
        # Never use unchecked string IDs in a URL.
        if not str(challenge_id).isdigit():
            raise ApiError("Invalid challenge ID")
        result = self._json(f"/api/v1/challenges/{int(challenge_id)}")
        if not isinstance(result, dict):
            raise ApiError("Invalid challenge detail")
        return result

    def attachment(self, path: str) -> bytes:
        # Only CTFd's signed file URLs, not external URLs embedded in descriptions.
        parsed = urlsplit(path)
        if parsed.scheme or parsed.netloc or not parsed.path.startswith("/files/"):
            raise ApiError("Unsafe or unsupported file URL blocked")
        return self._get(path, MAX_FILE_SIZE)
