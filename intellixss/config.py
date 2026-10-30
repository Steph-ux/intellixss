"""Runtime configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only, avoids config <-> auth cycle
    from intellixss.auth import AuthConfig


DEFAULT_UA_CHROME = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)

# Rotation pool: index 0 is always the primary UA so a scan keeps a stable
# fingerprint unless the caller explicitly opts into rotation.
DEFAULT_USER_AGENTS = [
    DEFAULT_UA_CHROME,
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]


def _default_auth() -> "AuthConfig":
    """Import AuthConfig lazily (auth imports this module)."""
    from intellixss.auth import AuthConfig

    return AuthConfig()


@dataclass
class Config:
    user_agent: str = DEFAULT_UA_CHROME
    timeout: float = 12.0
    rate_limit: float = 4.0
    max_payloads_per_param: int = 25
    max_crawl_depth: int = 2
    max_urls: int = 40
    use_browser: bool = True
    browser_timeout_ms: int = 12000
    browser_concurrency: int = 2
    workers: int = 4
    deep: bool = False  # header + redirect + json + graphql + upload
    aggressive: bool = False
    # Probe a short list of conventional parameter names on the seed path.
    # A lab (and more than a few real apps) reflects a parameter it never links
    # to or puts in a form; the only way a tester finds it is by trying the name.
    guess_params: bool = False
    verbose: bool = False
    silent: bool = False
    output: Optional[str] = None
    html_report: Optional[str] = None
    callback_url: str = ""
    # Resolved lazily to keep intellixss.config <-> intellixss.auth acyclic.
    auth: "AuthConfig" = field(default_factory=_default_auth)

    # --- Capability knobs (v3.3) ---
    user_agents: list = field(default_factory=lambda: list(DEFAULT_USER_AGENTS))
    adaptive_throttle: bool = True  # back off on 429/503, recover on 200s
    retries: int = 2  # transient network retries per request
    encoding_strategies: bool = True  # evolve URL encoding when app decodes once
    callback_verify: bool = False  # use --callback URL as OOB oracle
    max_confirm_per_host: int = 12  # cap Playwright navigations per host
    sample_budget: int = 0  # 0 = unlimited payloads per param (bounded by time)
    scan_timeout: float = 0.0  # 0 = unlimited wall clock for a scan

    default_params: list = field(
        default_factory=lambda: [
            "q", "query", "search", "s", "keyword", "name", "id", "page",
            "url", "redirect", "next", "callback", "return", "msg", "message",
            "text", "input", "data", "value", "term",
        ]
    )
