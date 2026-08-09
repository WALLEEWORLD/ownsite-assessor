"""Shared HTTP client with polite defaults for authorized self-tests."""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class AssessorClient:
    def __init__(
        self,
        timeout: float = 10.0,
        max_redirects: int = 5,
        user_agent: str = "OwnSiteAssessor/1.0 (+authorized-self-test)",
        session_cookie: str | None = None,
    ) -> None:
        self.timeout = timeout
        self.user_agent = user_agent
        self.session = requests.Session()
        self.session.max_redirects = max_redirects
        self.session.headers.update(
            {
                "User-Agent": user_agent,
                "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
            }
        )
        if session_cookie:
            # Raw Cookie header — operator-supplied for authenticated baseline
            self.session.headers["Cookie"] = session_cookie

        retry = Retry(
            total=2,
            backoff_factor=0.4,
            status_forcelist=(429, 502, 503, 504),
            allowed_methods=frozenset(["GET", "HEAD", "OPTIONS"]),
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def get(
        self,
        url: str,
        *,
        allow_redirects: bool = True,
        headers: dict[str, str] | None = None,
        stream: bool = False,
    ) -> requests.Response:
        return self.session.get(
            url,
            timeout=self.timeout,
            allow_redirects=allow_redirects,
            headers=headers,
            stream=stream,
        )

    def head(self, url: str, *, allow_redirects: bool = True) -> requests.Response:
        return self.session.head(
            url, timeout=self.timeout, allow_redirects=allow_redirects
        )

    def options(self, url: str) -> requests.Response:
        return self.session.options(url, timeout=self.timeout, allow_redirects=True)

    def request_meta(self, url: str) -> dict[str, Any]:
        """Safe GET that captures status, headers, timing, final URL."""
        try:
            resp = self.get(url, allow_redirects=True)
            return {
                "url": url,
                "final_url": str(resp.url),
                "status_code": resp.status_code,
                "headers": {k: v for k, v in resp.headers.items()},
                "elapsed_ms": int(resp.elapsed.total_seconds() * 1000),
                "redirected": urlparse(url).netloc != urlparse(str(resp.url)).netloc
                or urlparse(url).path != urlparse(str(resp.url)).path,
                "content_length": len(resp.content),
                "content_type": resp.headers.get("Content-Type", ""),
                "body_sample": resp.text[:2000] if resp.text else "",
                "error": None,
            }
        except requests.RequestException as exc:
            return {
                "url": url,
                "final_url": None,
                "status_code": None,
                "headers": {},
                "elapsed_ms": None,
                "redirected": False,
                "content_length": 0,
                "content_type": "",
                "body_sample": "",
                "error": f"{type(exc).__name__}: {exc}",
            }

    @staticmethod
    def build_url(scheme: str, host: str, path: str = "/") -> str:
        base = f"{scheme}://{host}"
        return urljoin(base + "/", path.lstrip("/"))
