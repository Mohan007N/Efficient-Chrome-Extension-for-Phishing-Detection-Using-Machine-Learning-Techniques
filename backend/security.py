"""
backend/security.py — SSRF Protection, IP-Pinned HTTP Fetching, Gzip-Bomb Defense, Privacy & Rate Limiting (v3.0)

Security guarantees:
- Resolves DNS once per hop and pins TCP connections directly to the validated public IP
  while preserving TLS SNI and strict hostname verification (prevents TOCTOU DNS rebinding).
- Blocks private, loopback, link-local (cloud metadata 169.254.169.254), multicast,
  reserved, unspecified, and carrier-grade NAT IP addresses on initial URL and all redirect hops.
- Permits only http:// and https:// schemes without embedded URL credentials.
- Enforces streaming compressed AND decompressed byte limits (prevents gzip bombs).
- Enforces bounded outbound fetch concurrency, timeouts, and socket cleanup.
- Strips forbidden credential/cookie/token keys from telemetry payloads.
- Supports bounded memory rate limiting with idle-key eviction and optional Redis backend.
"""

from __future__ import annotations

from collections import defaultdict, deque
import http.client
import ipaddress
import logging
import os
import secrets
import socket
import ssl
import threading
import time
from typing import Callable
import urllib.error
import urllib.request
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse
import zlib

logger = logging.getLogger("PhishingAPI.Security")

ALLOWED_SCHEMES = {"http", "https"}
DEFAULT_MAX_COMPRESSED_BYTES = 1_500_000
DEFAULT_MAX_DECOMPRESSED_BYTES = 2_500_000
DEFAULT_MAX_REDIRECTS = 3
DEFAULT_FETCH_TIMEOUT = 6.0

_CONCURRENCY_LIMIT = max(2, int(os.getenv("MAX_CONCURRENT_OUTBOUND_FETCHES", "16")))
OUTBOUND_FETCH_SEMAPHORE = threading.BoundedSemaphore(_CONCURRENCY_LIMIT)

FORBIDDEN_TELEMETRY_KEYS = {
    "password", "passwd", "pass", "pwd", "cookie", "cookies",
    "set-cookie", "authorization", "token", "auth_token", "access_token",
    "refresh_token", "id_token", "session", "session_id", "secret",
    "api_secret", "cvv", "cvc", "card_number", "pin", "otp",
}


class SSRFBlockedError(ValueError):
    """Raised when a URL targets a blocked IP range, scheme, or unsafe redirect."""


class PayloadTooLargeError(ValueError):
    """Raised when compressed or decompressed response bytes exceed safe limits (e.g., gzip bomb)."""


def is_forbidden_ip(ip_str: str) -> bool:
    """Return True if IP string is non-global, private, loopback, link-local, multicast, or invalid."""
    clean_ip = (ip_str or "").split("%", 1)[0].strip("[]")
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
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


def _is_forbidden_ip(ip_str: str) -> bool:
    return is_forbidden_ip(ip_str)


def is_private_or_local_target(url: str) -> bool:
    """Return True if URL explicitly targets localhost, .local, .internal, or private/loopback IP."""
    try:
        parsed = urlparse((url or "").strip())
        host = (parsed.hostname or "").strip().lower().rstrip(".")
    except Exception:
        return False
    if not host:
        return False
    if host in {"localhost", "ip6-localhost", "localhost.localdomain"} or host.endswith((".local", ".internal", ".localhost")):
        if host == "metadata.google.internal":
            return False
        return True
    try:
        ip_obj = ipaddress.ip_address(host.strip("[]"))
        return bool(ip_obj.is_private or ip_obj.is_loopback)
    except ValueError:
        return False


def validate_safe_url_and_resolve(
    url: str,
    resolve_dns: bool = True,
    dns_resolver: Callable | None = None,
) -> tuple[str, list[str]]:
    """
    Validate that a URL uses http/https, has no embedded credentials,
    and resolves exclusively to public global IP addresses.
    Returns `(normalized_clean_url, validated_ip_list)`.
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

    ip_literal = None
    try:
        ip_literal = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        ip_literal = None

    if ip_literal is not None:
        if is_forbidden_ip(str(ip_literal)):
            raise SSRFBlockedError(f"Blocked non-public IP address '{host}'.")
        return clean, [str(ip_literal)]

    if not resolve_dns:
        return clean, []

    resolver = dns_resolver or socket.getaddrinfo
    try:
        infos = resolver(host, parsed.port or (443 if scheme == "https" else 80), type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise SSRFBlockedError(f"Hostname DNS resolution failed for '{host}': {e}") from e

    ips = []
    seen = set()
    for item in infos:
        if item and len(item) >= 5 and item[4]:
            ip_val = str(item[4][0]).split("%", 1)[0]
            if ip_val not in seen:
                seen.add(ip_val)
                ips.append(ip_val)

    if not ips:
        raise SSRFBlockedError(f"No IP addresses resolved for '{host}'.")

    for ip in ips:
        if is_forbidden_ip(ip):
            raise SSRFBlockedError(f"Blocked SSRF target IP '{ip}' resolved for '{host}'.")

    return clean, ips


def validate_safe_url(url: str, resolve_dns: bool = True) -> str:
    """Backward-compatible wrapper returning clean validated URL string."""
    clean, _ = validate_safe_url_and_resolve(url, resolve_dns=resolve_dns)
    return clean


def safe_decompress_gzip(
    compressed_bytes: bytes,
    max_decompressed_bytes: int = DEFAULT_MAX_DECOMPRESSED_BYTES,
) -> bytes:
    """
    Incrementally decompress gzip stream while enforcing a strict maximum output size
    to defeat gzip bombs cleanly without unbounded memory allocation.
    """
    if not compressed_bytes:
        return b""
    decomp = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out_chunks: list[bytes] = []
    total_out = 0
    chunk_size = 65_536

    for offset in range(0, len(compressed_bytes), chunk_size):
        slice_bytes = compressed_bytes[offset:offset + chunk_size]
        remaining = max_decompressed_bytes - total_out
        if remaining <= 0:
            raise PayloadTooLargeError(f"Decompressed response exceeded safe limit ({max_decompressed_bytes} bytes).")
        part = decomp.decompress(slice_bytes, remaining + 1)
        total_out += len(part)
        if total_out > max_decompressed_bytes or decomp.unconsumed_tail:
            raise PayloadTooLargeError(f"Gzip bomb / excessive payload exceeded {max_decompressed_bytes} decompressed bytes.")
        out_chunks.append(part)

    tail = decomp.flush(max(1, max_decompressed_bytes - total_out + 1))
    if total_out + len(tail) > max_decompressed_bytes:
        raise PayloadTooLargeError(f"Gzip payload exceeded {max_decompressed_bytes} decompressed bytes.")
    if tail:
        out_chunks.append(tail)
    return b"".join(out_chunks)


def _read_bounded_response(
    resp,
    max_compressed_bytes: int,
    max_decompressed_bytes: int,
) -> bytes:
    """Stream response chunks with strict compressed and decompressed byte caps."""
    chunks: list[bytes] = []
    total_read = 0
    while True:
        piece = resp.read(65_536)
        if not piece:
            break
        total_read += len(piece)
        if total_read > max_compressed_bytes:
            raise PayloadTooLargeError(
                f"Response size exceeded maximum allowed limit ({max_compressed_bytes} bytes)."
            )
        chunks.append(piece)

    raw = b"".join(chunks)
    enc = (resp.headers.get("Content-Encoding") or "").lower()
    if "gzip" in enc:
        raw = safe_decompress_gzip(raw, max_decompressed_bytes=max_decompressed_bytes)
    return raw


class _NoAutoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Disable urllib automatic redirects so every hop is re-validated against SSRF rules."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection connecting TCP socket to pre-validated pinned IP (prevents DNS rebinding)."""

    def __init__(self, host: str, port: int | None = None, timeout: float = 6.0, pinned_ip: str | None = None, **kwargs):
        super().__init__(host, port=port, timeout=timeout, **kwargs)
        self._pinned_ip = pinned_ip

    def connect(self):
        target_host = self._pinned_ip or self.host
        self.sock = socket.create_connection((target_host, self.port), self.timeout, self.source_address)
        if self._tunnel_host:
            self._tunnel()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """
    HTTPSConnection connecting TCP socket to pre-validated pinned IP while passing original
    hostname for TLS SNI and strict X.509 certificate verification.
    """

    def __init__(
        self,
        host: str,
        port: int | None = None,
        timeout: float = 6.0,
        context: ssl.SSLContext | None = None,
        pinned_ip: str | None = None,
        **kwargs,
    ):
        ctx = context or ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        super().__init__(host, port=port, timeout=timeout, context=ctx, **kwargs)
        self._pinned_ip = pinned_ip

    def connect(self):
        target_host = self._pinned_ip or self.host
        sock = socket.create_connection((target_host, self.port), self.timeout, self.source_address)
        server_name = self._tunnel_host if self._tunnel_host else self.host
        self.sock = self._context.wrap_socket(sock, server_hostname=server_name)


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, pinned_ip: str | None = None):
        super().__init__()
        self._pinned_ip = pinned_ip

    def http_open(self, req):
        return self.do_open(
            lambda host, timeout=6.0, **kw: _PinnedHTTPConnection(host, timeout=timeout, pinned_ip=self._pinned_ip, **kw),
            req,
        )


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, pinned_ip: str | None = None, context: ssl.SSLContext | None = None):
        ctx = context or ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        super().__init__(context=ctx)
        self._pinned_ip = pinned_ip

    def https_open(self, req):
        return self.do_open(
            lambda host, timeout=6.0, **kw: _PinnedHTTPSConnection(
                host, timeout=timeout, context=self._context, pinned_ip=self._pinned_ip, **kw
            ),
            req,
        )


def safe_fetch_bytes(
    url: str,
    timeout: float = DEFAULT_FETCH_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_COMPRESSED_BYTES,
    max_decompressed_bytes: int = DEFAULT_MAX_DECOMPRESSED_BYTES,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    resolve_dns: bool = True,
    dns_resolver: Callable | None = None,
) -> tuple[str, int, bytes, list[str]]:
    """
    Safely fetch bytes over HTTP/HTTPS with DNS-pinned connections, per-hop SSRF validation,
    concurrency limiting, strict TLS verification, and gzip-bomb protection.
    Returns `(final_url, status_code, raw_bytes, redirect_chain)`.
    """
    current_url, resolved_ips = validate_safe_url_and_resolve(
        url, resolve_dns=resolve_dns, dns_resolver=dns_resolver
    )
    redirect_chain: list[str] = [current_url]
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; WebShield-SafetyBot/3.0)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "gzip",
    }

    acquired = OUTBOUND_FETCH_SEMAPHORE.acquire(timeout=min(float(timeout), 5.0))
    if not acquired:
        raise TimeoutError("Outbound HTTP fetch concurrency limit reached; request timed out.")

    try:
        for hop in range(max_redirects + 1):
            pinned_ip = resolved_ips[0] if resolved_ips else None
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = True
            ssl_ctx.verify_mode = ssl.CERT_REQUIRED
            opener = urllib.request.build_opener(
                _NoAutoRedirectHandler(),
                _PinnedHTTPHandler(pinned_ip=pinned_ip),
                _PinnedHTTPSHandler(pinned_ip=pinned_ip, context=ssl_ctx),
            )
            req = urllib.request.Request(current_url, headers=headers)
            try:
                with opener.open(req, timeout=timeout) as resp:
                    status = int(getattr(resp, "status", 200) or 200)
                    if status in (301, 302, 303, 307, 308):
                        loc = resp.headers.get("Location")
                        if not loc:
                            return current_url, status, b"", redirect_chain
                        if hop >= max_redirects:
                            raise SSRFBlockedError(f"Exceeded maximum redirect limit ({max_redirects}).")
                        next_url, resolved_ips = validate_safe_url_and_resolve(
                            urljoin(current_url, loc),
                            resolve_dns=resolve_dns,
                            dns_resolver=dns_resolver,
                        )
                        redirect_chain.append(next_url)
                        current_url = next_url
                        continue

                    raw = _read_bounded_response(resp, max_bytes, max_decompressed_bytes)
                    return current_url, status, raw, redirect_chain
            except urllib.error.HTTPError as he:
                status = int(getattr(he, "code", 500) or 500)
                if status in (301, 302, 303, 307, 308):
                    loc = he.headers.get("Location")
                    if loc:
                        if hop >= max_redirects:
                            raise SSRFBlockedError(f"Exceeded maximum redirect limit ({max_redirects}).")
                        next_url, resolved_ips = validate_safe_url_and_resolve(
                            urljoin(current_url, loc),
                            resolve_dns=resolve_dns,
                            dns_resolver=dns_resolver,
                        )
                        redirect_chain.append(next_url)
                        current_url = next_url
                        continue
                raw = _read_bounded_response(he, max_bytes, max_decompressed_bytes)
                return current_url, status, raw, redirect_chain
    finally:
        OUTBOUND_FETCH_SEMAPHORE.release()

    raise SSRFBlockedError(f"Exceeded maximum redirect limit ({max_redirects}).")


def safe_fetch_html(
    url: str,
    timeout: float = DEFAULT_FETCH_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_COMPRESSED_BYTES,
    max_decompressed_bytes: int = DEFAULT_MAX_DECOMPRESSED_BYTES,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    resolve_dns: bool = True,
    dns_resolver: Callable | None = None,
) -> tuple[str, int, str, list[str]]:
    """
    Safely fetch UTF-8 HTML over HTTP/HTTPS with DNS pinning, SSRF checks, and gzip-bomb limits.
    Returns `(final_url, status_code, html_text, redirect_chain)`.
    """
    final_url, status, raw, chain = safe_fetch_bytes(
        url,
        timeout=timeout,
        max_bytes=max_bytes,
        max_decompressed_bytes=max_decompressed_bytes,
        max_redirects=max_redirects,
        resolve_dns=resolve_dns,
        dns_resolver=dns_resolver,
    )
    return final_url, status, raw.decode("utf-8", errors="ignore"), chain


def sanitize_telemetry_dict(payload: dict) -> dict:
    """Recursively strip accidentally submitted credential/cookie/token keys from telemetry."""
    if not isinstance(payload, dict):
        return {}
    clean: dict = {}
    for k, v in payload.items():
        if str(k).lower() in FORBIDDEN_TELEMETRY_KEYS:
            continue
        if isinstance(v, dict):
            clean[k] = sanitize_telemetry_dict(v)
        else:
            clean[k] = v
    return clean


def redact_url_query_params(raw_url: str) -> str:
    """
    Remove query values and fragments before persisting URLs (feedback logs/analytics)
    so tokens, OTPs, emails, and session IDs are never written to disk.
    """
    clean = (raw_url or "").strip()
    if not clean:
        return ""
    parsed = urlparse(clean)
    if parsed.query:
        keys = [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]
        redacted_q = "&".join(f"{k}=REDACTED" for k in keys[:10])
    else:
        redacted_q = ""
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, redacted_q, ""))


def check_api_key_authorized(headers) -> tuple[bool, bool]:
    """
    Verify optional `WEBSHIELD_API_KEY` protection against `X-API-Key` or `Authorization: Bearer`.
    Returns `(auth_configured, is_authorized)`. When `WEBSHIELD_API_KEY` is blank, returns `(False, True)`.
    """
    expected = (os.getenv("WEBSHIELD_API_KEY") or "").strip()
    if not expected:
        return False, True
    provided = (headers.get("x-api-key") or headers.get("X-API-Key") or "").strip()
    if not provided:
        auth_hdr = (headers.get("authorization") or headers.get("Authorization") or "").strip()
        if auth_hdr.lower().startswith("bearer "):
            provided = auth_hdr[7:].strip()
    return True, bool(provided and secrets.compare_digest(provided, expected))


def get_allowed_cors_origins() -> list[str]:
    """
    Parse explicit CORS origins from environment (`ALLOWED_ORIGINS`), rejecting wildcard
    `*` in strict/production mode when `STRICT_CORS=1`.
    """
    raw = (os.getenv("ALLOWED_ORIGINS") or "").strip()
    if raw:
        origins = [o.strip() for o in raw.split(",") if o.strip()]
    else:
        origins = [
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        ]
    strict = os.getenv("STRICT_CORS", "1").strip() == "1"
    if strict:
        origins = [o for o in origins if o != "*"]
    return origins or ["http://127.0.0.1:8000"]


class RateLimiter:
    """
    Thread-safe sliding-window rate limiter with idle-key eviction and optional Redis backend.
    Configure `REDIS_URL` for multi-worker distributed rate limiting; otherwise bounds memory
    per single worker via automatic stale-key cleanup.
    """

    def __init__(self, max_requests_per_min: int | None = None, max_tracked_keys: int = 10_000):
        env_lim = os.getenv("RATE_LIMIT_PER_MIN", "180")
        self.max_requests = max_requests_per_min if max_requests_per_min is not None else int(env_lim)
        self.max_tracked_keys = max_tracked_keys
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._ops = 0
        self._redis = None

        redis_url = (os.getenv("REDIS_URL") or "").strip()
        if redis_url:
            try:
                import redis
                self._redis = redis.Redis.from_url(redis_url, decode_responses=True, socket_timeout=0.5)
            except Exception as e:
                logger.warning(f"Redis rate limiter unavailable ({e}); using bounded local fallback.")

    def _evict_stale(self, cutoff: float):
        stale_keys = [k for k, q in self._hits.items() if not q or q[-1] < cutoff]
        for k in stale_keys:
            del self._hits[k]
        if len(self._hits) > self.max_tracked_keys:
            overflow = len(self._hits) - self.max_tracked_keys
            oldest = sorted(self._hits.items(), key=lambda kv: kv[1][-1] if kv[1] else 0.0)[:overflow]
            for k, _ in oldest:
                del self._hits[k]

    def allow(self, client_key: str) -> bool:
        if self.max_requests <= 0:
            return True

        if self._redis is not None:
            try:
                now_bucket = int(time.time() // 60)
                rkey = f"webshield:rl:{client_key}:{now_bucket}"
                cnt = int(self._redis.incr(rkey))
                if cnt == 1:
                    self._redis.expire(rkey, 70)
                return cnt <= self.max_requests
            except Exception as e:
                logger.warning(f"Redis rate-limit check failed ({e}); falling back to memory.")

        now = time.time()
        cutoff = now - 60.0
        with self._lock:
            self._ops += 1
            if client_key not in self._hits and len(self._hits) >= self.max_tracked_keys:
                self._evict_stale(cutoff)
                while len(self._hits) >= self.max_tracked_keys:
                    oldest_key = min(self._hits.items(), key=lambda kv: kv[1][-1] if kv[1] else 0.0)[0]
                    del self._hits[oldest_key]
            elif self._ops % 256 == 0:
                self._evict_stale(cutoff)
            q = self._hits[client_key]
            while q and q[0] < cutoff:
                q.popleft()
            if len(q) >= self.max_requests:
                return False
            q.append(now)
            return True
