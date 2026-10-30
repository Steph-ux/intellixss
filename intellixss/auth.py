"""Authentication helpers for authenticated scans."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Dict, Optional
from urllib.parse import urljoin

import aiohttp

from intellixss.config import Config


@dataclass
class AuthConfig:
    cookie: str = ""
    bearer: str = ""
    basic: str = ""  # user:pass
    header: str = ""  # Name: value  (repeat via list later)
    headers: Dict[str, str] = field(default_factory=dict)
    # Form login
    login_url: str = ""
    username: str = ""
    password: str = ""
    username_field: str = "username"
    password_field: str = "password"


# Attributes that may follow a ``Cookie``-style value. They are not cookies:
# a real ``Cookie`` header never carries them, but they are pasted verbatim from
# a ``Set-Cookie`` response, and turning ``SameSite`` into a cookie named
# ``SameSite`` sends a header the server reads as a session it never issued.
_COOKIE_ATTRIBUTES = {
    "secure",
    "httponly",
    "samesite",
    "path",
    "domain",
    "expires",
    "max-age",
    "priority",
    "partitioned",
}


def parse_cookie_string(cookie_str: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not cookie_str:
        return out
    for part in cookie_str.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        name = k.strip()
        if not name or name.lower() in _COOKIE_ATTRIBUTES or " " in name:
            continue
        out[name] = v.strip()
    return out


def parse_header_string(header_str: str) -> Dict[str, str]:
    if not header_str or ":" not in header_str:
        return {}
    name, val = header_str.split(":", 1)
    return {name.strip(): val.strip()}


def build_auth_headers(auth: AuthConfig) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    headers.update(auth.headers)
    if auth.bearer:
        token = auth.bearer
        if not token.lower().startswith("bearer "):
            token = f"Bearer {token}"
        headers["Authorization"] = token
    if auth.basic and ":" in auth.basic:
        user, pwd = auth.basic.split(":", 1)
        raw = base64.b64encode(f"{user}:{pwd}".encode()).decode()
        headers["Authorization"] = f"Basic {raw}"
    if auth.header:
        headers.update(parse_header_string(auth.header))
    return headers


def build_auth_cookies(auth: AuthConfig) -> Dict[str, str]:
    return parse_cookie_string(auth.cookie)


async def form_login(
    config: Config,
    auth: AuthConfig,
    base_url: str,
    log=None,
) -> tuple[Dict[str, str], Dict[str, str], bool, str]:
    """
    POST credentials to login_url. Returns (headers, cookies, success, detail).
    """
    log = log or (lambda *a, **k: None)
    if not auth.login_url or not auth.username:
        return {}, {}, False, "missing login_url/username"

    login = urljoin(base_url.rstrip("/") + "/", auth.login_url.lstrip("/"))
    headers = build_auth_headers(auth)
    cookies = build_auth_cookies(auth)

    timeout = aiohttp.ClientTimeout(total=config.timeout)
    async with aiohttp.ClientSession(
        timeout=timeout,
        headers={"User-Agent": config.user_agent, **headers},
        cookie_jar=aiohttp.CookieJar(unsafe=True),
    ) as session:
        if cookies:
            session.cookie_jar.update_cookies(cookies)

        # Fetch login page for hidden fields (csrf)
        extra = {}
        try:
            async with session.get(login) as resp:
                html = await resp.text(errors="replace")
            for m in re.finditer(
                r'<input[^>]+type=["\']hidden["\'][^>]*>', html, re.I
            ):
                tag = m.group(0)
                nm = re.search(r'name=["\']([^"\']+)["\']', tag, re.I)
                val = re.search(r'value=["\']([^"\']*)["\']', tag, re.I)
                if nm:
                    extra[nm.group(1)] = val.group(1) if val else ""
        except Exception:
            pass

        data = {
            **extra,
            auth.username_field: auth.username,
            auth.password_field: auth.password,
        }
        try:
            async with session.post(login, data=data, allow_redirects=True) as resp:
                body = await resp.text(errors="replace")
                status = resp.status
                jar_cookies = {
                    c.key: c.value for c in session.cookie_jar
                }
        except Exception as e:
            return headers, cookies, False, f"login_error:{e}"

        # Heuristic success: got cookies or not obvious failure
        fail = re.search(
            r"invalid|incorrect|failed|wrong password|login error",
            body,
            re.I,
        )
        success = bool(jar_cookies) and not fail and status < 500
        if success:
            log(f"[*] Form login OK → cookies={list(jar_cookies.keys())}", "info")
        else:
            log(f"[!] Form login uncertain status={status}", "warn")
        cookies.update(jar_cookies)
        return headers, cookies, success, f"status={status}"
