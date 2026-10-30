"""Async HTTP client with rate limiting, retries, adaptive throttling and auth."""

from __future__ import annotations

import asyncio
import random
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import aiohttp

from intellixss.config import Config
from intellixss import encode as encode_mod

# Statuses worth retrying (transient) — NOT 5xx produced by our payload.
_TRANSIENT = {429, 502, 503, 504}
# Statuses that signal "slow down"
_BACKOFF = {429, 503}


class HttpClient:
    def __init__(
        self,
        config: Config,
        session: Optional[aiohttp.ClientSession] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, Any]] = None,
    ):
        self.config = config
        self._session = session
        self._owns_session = session is None
        self._last_request = 0.0
        self._lock = asyncio.Lock()
        self.extra_headers = dict(extra_headers or {})
        self.cookies = dict(cookies or {})
        # adaptive throttle state
        self._rate = max(0.1, config.rate_limit)
        self._rate_cap = max(0.1, config.rate_limit)
        self._rate_floor = max(0.2, config.rate_limit / 8.0)
        self._backoff_until = 0.0
        self._ua_index = 0
        # stats
        self.requests = 0
        self.rate_limited = 0
        self.retries = 0

    async def __aenter__(self) -> "HttpClient":
        if self._session is None:
            timeout = aiohttp.ClientTimeout(total=self.config.timeout, sock_connect=min(10.0, self.config.timeout))
            headers = {"User-Agent": self.config.user_agent, "Accept": "*/*"}
            headers.update(self.extra_headers)
            jar = aiohttp.CookieJar(unsafe=True)
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                headers=headers,
                cookie_jar=jar,
                trust_env=True,
            )
            if self.cookies:
                self._session.cookie_jar.update_cookies(self.cookies)
        return self

    async def __aexit__(self, *args) -> None:
        if self._owns_session and self._session:
            await self._session.close()
            self._session = None

    # ------------------------------------------------------------------
    # auth mutation
    # ------------------------------------------------------------------

    def set_auth_headers(self, headers: Dict[str, str]) -> None:
        self.extra_headers.update(headers)
        if self._session is not None:
            self._session.headers.update(headers)

    def set_cookies(self, cookies: Dict[str, Any]) -> None:
        self.cookies.update(cookies)
        if self._session is not None:
            self._session.cookie_jar.update_cookies(cookies)

    # ------------------------------------------------------------------
    # core request
    # ------------------------------------------------------------------

    async def request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
        json_body: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        multipart: Optional[aiohttp.FormData] = None,
        allow_redirects: bool = True,
    ) -> Tuple[int, str, Dict[str, str], str]:
        """
        Returns (status, body, headers, final_url).
        On network error returns (0, "", {}, url). Retries transient failures.
        """
        assert self._session is not None
        attempts = max(0, int(self.config.retries)) + 1
        last = (0, "", {}, url)
        for attempt in range(attempts):
            await self._throttle()
            req_headers = dict(self.extra_headers)
            if headers:
                req_headers.update(headers)
            if self.config.user_agents and attempt > 0:
                # Rotate UA only on retry (keeps the baseline fingerprint stable)
                req_headers.setdefault("User-Agent", self._rotate_ua())
            try:
                kwargs: Dict[str, Any] = {
                    "method": method.upper(),
                    "url": url,
                    "headers": req_headers or None,
                    "allow_redirects": allow_redirects,
                }
                if method.upper() == "GET" and params is not None:
                    kwargs["params"] = params
                if multipart is not None:
                    kwargs["data"] = multipart
                elif json_body is not None:
                    kwargs["json"] = json_body
                elif data is not None and method.upper() != "GET":
                    kwargs["data"] = data

                self.requests += 1
                async with self._session.request(**kwargs) as resp:
                    body = await resp.text(errors="replace")
                    hdrs = {k: v for k, v in resp.headers.items()}
                    final = str(resp.url)
                    status = resp.status
                    self._observe(status, hdrs)
                    last = (status, body, hdrs, final)
                    if status in _TRANSIENT and attempt + 1 < attempts:
                        self.retries += 1
                        await asyncio.sleep(0.4 * (2**attempt) + random.uniform(0, 0.2))
                        continue
                    return last
            except asyncio.TimeoutError:
                last = (0, "", {}, url)
            except aiohttp.ClientError:
                last = (0, "", {}, url)
            except Exception as exc:  # defensive: never crash a scan
                return 0, "", {}, f"{url}#error={exc}"
            if attempt + 1 < attempts:
                self.retries += 1
                await asyncio.sleep(0.3 * (2**attempt) + random.uniform(0, 0.15))
        return last

    # ------------------------------------------------------------------
    # injection helpers
    # ------------------------------------------------------------------

    async def inject(
        self,
        url: str,
        param: str,
        value: str,
        method: str = "GET",
        base_data: Optional[Dict[str, str]] = None,
        encoding_level: int = 0,
    ) -> Tuple[int, str, Dict[str, str], str]:
        """
        Inject *value* into a query/body parameter or URL fragment.

        *encoding_level* rewrites the raw query string (double-encoding, HTML
        entities) when the server decodes input once before echoing it.
        """
        if param in ("#fragment", "fragment", "#"):
            base = url.split("#")[0]
            st, body, hdrs, fin = await self.request("GET", base)
            return st, body, hdrs, f"{fin}#{value}"
        if method.upper() == "GET":
            injected = (
                encode_mod.set_query_param_encoded(url, param, value, encoding_level)
                if encoding_level > 0
                else _set_query_param(url, param, value)
            )
            return await self.request("GET", injected)
        data = dict(base_data or {})
        data[param] = encode_mod.encode_value(value, encoding_level)
        return await self.request("POST", url, data=data)

    async def inject_json(
        self,
        url: str,
        field: str,
        value: str,
        base: Optional[Dict[str, Any]] = None,
        method: str = "POST",
    ) -> Tuple[int, str, Dict[str, str], str]:
        body = dict(base or {})
        body[field] = value
        return await self.request(method, url, json_body=body)

    async def get_headers(self, url: str) -> Dict[str, str]:
        _, _, hdrs, _ = await self.request("GET", url)
        return hdrs

    # ------------------------------------------------------------------
    # throttling
    # ------------------------------------------------------------------

    def _rotate_ua(self) -> str:
        pool: List[str] = self.config.user_agents or [self.config.user_agent]
        self._ua_index = (self._ua_index + 1) % len(pool)
        return pool[self._ua_index]

    def _observe(self, status: int, headers: Dict[str, str]) -> None:
        """Adaptive rate: slow down on 429/503, recover on healthy responses."""
        if not self.config.adaptive_throttle:
            return
        if status in _BACKOFF:
            self.rate_limited += 1
            retry_after = headers.get("Retry-After") or headers.get("retry-after")
            delay = 2.0
            if retry_after:
                try:
                    delay = min(30.0, float(retry_after))
                except ValueError:
                    delay = 3.0
            self._rate = max(self._rate_floor, self._rate / 2.0)
            self._backoff_until = max(self._backoff_until, time.monotonic() + delay)
            return
        if status and status < 400:
            # Additive increase toward the configured cap
            self._rate = min(self._rate_cap, self._rate + 0.1)

    async def _throttle(self) -> None:
        if self.config.adaptive_throttle:
            now = time.monotonic()
            if now < self._backoff_until:
                await asyncio.sleep(self._backoff_until - now)
        if self._rate <= 0:
            return
        async with self._lock:
            min_interval = 1.0 / self._rate
            now = time.monotonic()
            wait = self._last_request + min_interval - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request = time.monotonic()


def _set_query_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    q = dict(parse_qsl(parsed.query, keep_blank_values=True))
    q[param] = value
    new_query = urlencode(q, doseq=True)
    return urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
    )
