"""
backend/security.py — SSRF Protection, Safe HTTP Fetching, Privacy Sanitization & Rate Limiting

Security guarantees:
- Blocks private, loopback, link-local (cloud metadata 169.254.169.254), multicast,
  reserved, and unspecified IP addresses on both initial URL and all redirect hops.
- Permits only http:// and https:// schemes.
- Caps redirect depth (<= 3), response payload size (<= 1.5 MB), and timeouts.
- Never executes webpage JavaScript on the backend.
- Strips forbidden credential/cookie/token keys if present in telemetry payloads.
"""

from __future__ import annotations

from collections import defaultdict, deque
import gzip
import ipaddress
import os
import socket
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlparse

ALLOWED_SCHEMES = {"http", "https"}
FORBIDDEN_TELEMETRY_KEYS = {
    "password", "passwd", "pass", "cookie", "cookies",
    "token", "auth_token", "access_token", "refresh_token",
    "secret", "api_secret", "cvv", "cvc", "card_number", "pin",
}


class SSRFBlockedError(ValueError):
    """Raised when a URL targets a blocked IP range, scheme, or unsafe redirect."""


def _is_forbidden_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    if ip_obj.version == 6 and ip_obj.ipv4_mapped:
        ip_obj = ip_obj.ipv4_mapped
    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
        or not ip_obj.is_global
    )


def validate_safe_url(url: str, resolve_dns: bool = True) -> str:
    """
    Validate that a URL uses http/https, has no embedded userinfo/credentials,
    and resolves exclusively to public global IP addresses.
    """
    clean = (url or "").strip()
    if not clean or len(clean) > 2048:
        raise SSRFBlockedError("URL is empty or exceeds maximum allowed length (2048).")

    parsed = urlparse(clean)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise SSRFBlockedError(f"Unsupported URL scheme '{scheme}'. Only http and https are permitted.")

    if parsed.username or parsed.password:
        raise SSRFBlockedError("Embedded URL credentials are not permitted.")

    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise SSRFBlockedError("URL hostname is missing.")

    if host in {"localhost", "ip6-localhost", "metadata.google.internal"} or host.endswith((".local", ".internal")):
        raise SSRFBlockedError(f"Blocked internal/reserved hostname '{host}'.")

    # Direct IP literal check before DNS (avoid catching SSRFBlockedError as ValueError)
    ip_literal = None
    try:
        ip_literal = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        ip_literal = None
    if ip_literal is not None and _is_forbidden_ip(str(ip_literal)):
        raise SSRFBlockedError(f"Blocked non-public IP address '{host}'.")

    if resolve_dns:
        try:
            infos = socket.getaddrinfo(host, parsed.port or (443 if scheme == "https" else 80), type=socket.SOCK_STREAM)
        except socket.gaierror as e:
            raise SSRFBlockedError(f"Hostname DNS resolution failed for '{host}': {e}") from e

        ips = {item[4][0] for item in infos if item[4]}
        if not ips:
            raise SSRFBlockedError(f"No IP addresses resolved for '{host}'.")
        for ip in ips:
            if _is_forbidden_ip(ip):
                raise SSRFBlockedError(f"Blocked SSRF target IP '{ip}' resolved for '{host}'.")

    return clean


class _NoAutoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Disable urllib automatic redirects so every hop is re-validated against SSRF rules."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def safe_fetch_html(
    url: str,
    timeout: float = 6.0,
    max_bytes: int = 1_500_000,
    max_redirects: int = 3,
    resolve_dns: bool = True,
) -> tuple[str, int, str, list[str]]:
    """
    Safely fetch HTML over HTTP/HTTPS with SSRF validation on every redirect hop.
    Returns (final_url, status_code, html_text, redirect_chain).
    """
    current_url = validate_safe_url(url, resolve_dns=resolve_dns)
    redirect_chain: list[str] = [current_url]
    opener = urllib.request.build_opener(_NoAutoRedirectHandler())
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; PhishGuard-SafetyBot/2.0)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "gzip",
    }

    for hop in range(max_redirects + 1):
        req = urllib.request.Request(current_url, headers=headers)
        try:
            with opener.open(req, timeout=timeout) as resp:
                status = int(getattr(resp, "status", 200) or 200)
                if status in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("Location")
                    if not loc:
                        return current_url, status, "", redirect_chain
                    if hop >= max_redirects:
                        raise SSRFBlockedError(f"Exceeded maximum redirect limit ({max_redirects}).")
                    next_url = validate_safe_url(urljoin(current_url, loc), resolve_dns=resolve_dns)
                    redirect_chain.append(next_url)
                    current_url = next_url
                    continue

                raw = resp.read(max_bytes + 1)
                if len(raw) > max_bytes:
                    raw = raw[:max_bytes]
                if "gzip" in (resp.headers.get("Content-Encoding") or "").lower():
                    try:
                        raw = gzip.decompress(raw)
                    except Exception:
                        pass
                return current_url, status, raw.decode("utf-8", errors="ignore"), redirect_chain
        except urllib.error.HTTPError as he:
            status = int(getattr(he, "code", 500) or 500)
            if status in (301, 302, 303, 307, 308):
                loc = he.headers.get("Location")
                if loc:
                    if hop >= max_redirects:
                        raise SSRFBlockedError(f"Exceeded maximum redirect limit ({max_redirects}).")
                    next_url = validate_safe_url(urljoin(current_url, loc), resolve_dns=resolve_dns)
                    redirect_chain.append(next_url)
                    current_url = next_url
                    continue
            raw = he.read(max_bytes)
            if "gzip" in (he.headers.get("Content-Encoding") or "").lower():
                try:
                    raw = gzip.decompress(raw)
                except Exception:
                    pass
            return current_url, status, raw.decode("utf-8", errors="ignore"), redirect_chain

    raise SSRFBlockedError(f"Exceeded maximum redirect limit ({max_redirects}).")


def sanitize_telemetry_dict(payload: dict) -> dict:
    """Remove any accidentally submitted credential/cookie/secret keys from telemetry payloads."""
    if not isinstance(payload, dict):
        return {}
    return {
        k: v
        for k, v in payload.items()
        if str(k).lower() not in FORBIDDEN_TELEMETRY_KEYS
    }


class RateLimiter:
    """Thread-safe sliding-window per-IP rate limiter."""

    def __init__(self, max_requests_per_min: int | None = None):
        env_lim = os.getenv("RATE_LIMIT_PER_MIN", "180")
        self.max_requests = max_requests_per_min if max_requests_per_min is not None else int(env_lim)
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, client_key: str) -> bool:
        if self.max_requests <= 0:
            return True
        now = time.time()
        cutoff = now - 60.0
        with self._lock:
            q = self._hits[client_key]
            while q and q[0] < cutoff:
                q.popleft()
            if len(q) >= self.max_requests:
                return False
            q.append(now)
            return True

