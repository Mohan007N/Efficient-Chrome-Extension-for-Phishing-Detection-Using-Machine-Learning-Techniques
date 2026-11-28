import gzip
import os
import shutil
import socket
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.intel import UnauthorizedIntelEngine
from backend.security import (
    PayloadTooLargeError,
    RateLimiter,
    SSRFBlockedError,
    get_allowed_cors_origins,
    safe_decompress_gzip,
    sanitize_telemetry_dict,
    validate_safe_url_and_resolve,
)
from src.playwright_inspector import should_block_playwright_request


def test_dns_rebinding_resolution_validation():
    # Simulated resolver that resolves first public IP then attempts internal rebind on another host
    def fake_public_resolver(host, port, type=socket.SOCK_STREAM):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    clean, ips = validate_safe_url_and_resolve(
        "https://example.invalid/login",
        resolve_dns=True,
        dns_resolver=fake_public_resolver,
    )
    assert ips == ["93.184.216.34"]
    assert clean.startswith("https://")

    def fake_rebind_resolver(host, port, type=socket.SOCK_STREAM):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    with pytest.raises(SSRFBlockedError):
        validate_safe_url_and_resolve(
            "https://rebind-attack.invalid/",
            resolve_dns=True,
            dns_resolver=fake_rebind_resolver,
        )


def test_gzip_bomb_protection_caps_decompressed_bytes():
    huge_plain = b"A" * 600_000
    compressed = gzip.compress(huge_plain)
    assert len(compressed) < 10_000

    with pytest.raises(PayloadTooLargeError):
        safe_decompress_gzip(compressed, max_decompressed_bytes=100_000)

    small = gzip.compress(b"<html><body>ok</body></html>")
    assert b"ok" in safe_decompress_gzip(small, max_decompressed_bytes=10_000)


def test_cors_rate_limit_eviction_and_telemetry_sanitization(monkeypatch):
    monkeypatch.setenv("ALLOWED_ORIGINS", "*,https://app.webshield.invalid")
    monkeypatch.setenv("STRICT_CORS", "1")
    origins = get_allowed_cors_origins()
    assert "*" not in origins
    assert "https://app.webshield.invalid" in origins

    rl = RateLimiter(max_requests_per_min=3, max_tracked_keys=5)
    assert rl.allow("1.1.1.1") is True
    assert rl.allow("1.1.1.1") is True
    assert rl.allow("1.1.1.1") is True
    assert rl.allow("1.1.1.1") is False

    for i in range(10):
        rl.allow(f"2.2.2.{i}")
    assert len(rl._hits) <= 5

    sanitized = sanitize_telemetry_dict({
        "url": "https://example.com",
        "password": "secret",
        "nested": {"cookies": "abc=1", "cvv": "999", "safe_flag": 1},
    })
    assert "password" not in sanitized
    assert "cookies" not in sanitized["nested"]
    assert "cvv" not in sanitized["nested"]
    assert sanitized["nested"]["safe_flag"] == 1


def test_playwright_ssrf_request_filtering():
    def fake_pub_dns(host, port, type=socket.SOCK_STREAM):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("142.250.190.46", port))]

    assert should_block_playwright_request("http://127.0.0.1:8000/admin", resolve_dns=False)[0] is True
    assert should_block_playwright_request("http://169.254.169.254/latest/meta-data", resolve_dns=False)[0] is True
    assert should_block_playwright_request("file:///etc/passwd", resolve_dns=False)[0] is True
    assert should_block_playwright_request("https://sites.google.com/view/test", resolve_dns=True, dns_resolver=fake_pub_dns)[0] is False


def test_threat_intel_honest_failure_visibility_and_hosted_subdomain_protection():
    empty_dir = tempfile.mkdtemp(prefix="ws_missing_intel_")
    try:
        engine = UnauthorizedIntelEngine(dataset_dir=empty_dir)
        engine.load()
        summary = engine.status_summary()
        assert summary["loaded"] is False
        assert summary["degraded"] is True
        assert len(summary["errors"]) >= 2

        # Multi-tenant user content subdomains must NEVER inherit TRUSTED_DOMAINS immunity
        assert engine.is_trusted("sites.google.com") is False
        assert engine.is_trusted("google.com") is True
    finally:
        shutil.rmtree(empty_dir, ignore_errors=True)
