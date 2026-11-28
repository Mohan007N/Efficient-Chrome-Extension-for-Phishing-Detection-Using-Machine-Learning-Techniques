"""
src/playwright_inspector.py — Sandboxed SSRF-Guarded Live Browser DOM Inspector (v3.0)

Provides optional live rendered-DOM inspection via Playwright inside an isolated,
non-persistent browser context with strict SSRF interception on EVERY request and redirect:
- Blocks file://, data://, chrome://, private IPv4/IPv6 ranges, loopback, and cloud metadata.
- Caps sub-requests, skips heavy media/font assets, disables downloads, and enforces hard timeouts.
- Distinguishes clearly between `live_browser_dom` and `static_html_fallback`.
"""

from __future__ import annotations

import logging
import os
from urllib.parse import urlparse

from backend.security import SSRFBlockedError, validate_safe_url, validate_safe_url_and_resolve
from src.dom_features import extract_dom_features_from_html
from src.features import extract_root_domain

logger = logging.getLogger("PhishingAPI.Playwright")

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_PKG_AVAILABLE = True
except Exception:
    sync_playwright = None
    PLAYWRIGHT_PKG_AVAILABLE = False


def is_playwright_available() -> bool:
    """Return True only when Playwright SDK and at least one compatible browser executable exist."""
    if not PLAYWRIGHT_PKG_AVAILABLE:
        return False
    # Check standard Windows / Linux browser locations without triggering heavy downloads
    candidates = [
        os.path.expanduser(r"~\AppData\Local\ms-playwright"),
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/usr/bin/google-chrome",
    ]
    return any(os.path.exists(p) for p in candidates)


def should_block_playwright_request(req_url: str, resolve_dns: bool = True, dns_resolver=None) -> tuple[bool, str]:
    """
    Pure SSRF gate evaluated on every Playwright request/sub-request.
    Returns `(blocked, reason)`.
    """
    try:
        validate_safe_url_and_resolve(req_url, resolve_dns=resolve_dns, dns_resolver=dns_resolver)
        return False, ""
    except SSRFBlockedError as se:
        return True, str(se)
    except Exception as e:
        return True, f"Unsafe request rejected: {e}"


def inspect_page_with_playwright(
    url: str,
    timeout_ms: int = 8000,
    max_requests: int = 60,
    max_html_chars: int = 1_500_000,
) -> dict:
    """
    Safely render `url` in a fresh ephemeral headless browser context with strict
    SSRF route interception and resource limits. Returns structured DOM telemetry,
    network observations, redirect chain, and explicit observation-mode metadata.
    """
    # Validate initial entry URL prior to launching browser
    clean_url = validate_safe_url(url, resolve_dns=True)

    if not PLAYWRIGHT_PKG_AVAILABLE:
        return {
            "available": False,
            "analysis_mode": "static_html_fallback",
            "reason": "Playwright package not installed.",
        }

    req_counter = {"count": 0, "blocked": [], "external_destinations": set()}
    redirect_chain: list[str] = [clean_url]
    root = extract_root_domain((urlparse(clean_url).hostname or "").lower())

    try:
        with sync_playwright() as pw:
            browser = None
            for launch_kwargs in (
                {"headless": True},
                {"headless": True, "channel": "msedge"},
                {"headless": True, "channel": "chrome"},
            ):
                try:
                    browser = pw.chromium.launch(**launch_kwargs)
                    break
                except Exception:
                    continue

            if browser is None:
                return {
                    "available": False,
                    "analysis_mode": "static_html_fallback",
                    "reason": "No Chromium/Chrome/Edge runtime binary found for Playwright.",
                }

            try:
                context = browser.new_context(
                    accept_downloads=False,
                    ignore_https_errors=False,
                    java_script_enabled=True,
                )
                page = context.new_page()
                page.set_default_timeout(timeout_ms)

                def _route_handler(route):
                    r_url = route.request.url
                    r_type = route.request.resource_type
                    req_counter["count"] += 1
                    if req_counter["count"] > max_requests:
                        req_counter["blocked"].append("max_subrequest_limit")
                        route.abort()
                        return
                    if r_type in ("media", "font", "websocket"):
                        route.abort()
                        return
                    blocked, reason = should_block_playwright_request(r_url)
                    if blocked:
                        req_counter["blocked"].append(f"{r_url[:80]} ({reason})")
                        route.abort()
                        return
                    r_host = (urlparse(r_url).hostname or "").lower()
                    if r_host and extract_root_domain(r_host) != root:
                        req_counter["external_destinations"].add(extract_root_domain(r_host))
                    route.continue_()

                context.route("**/*", _route_handler)

                def _on_frame_nav(frame):
                    if frame == page.main_frame and frame.url.startswith(("http://", "https://")):
                        if frame.url not in redirect_chain:
                            redirect_chain.append(frame.url)

                page.on("framenavigated", _on_frame_nav)

                resp = page.goto(clean_url, wait_until="domcontentloaded", timeout=timeout_ms)
                try:
                    page.wait_for_timeout(750)
                except Exception:
                    pass

                final_url = page.url or clean_url
                validate_safe_url(final_url, resolve_dns=True)
                rendered_html = (page.content() or "")[:max_html_chars]
                dom_feats = extract_dom_features_from_html(
                    final_url,
                    rendered_html,
                    analysis_mode="live_browser_dom",
                )
                return {
                    "available": True,
                    "analysis_mode": "live_browser_dom",
                    "final_url": final_url,
                    "http_status": int(resp.status) if resp else None,
                    "html": rendered_html,
                    "dom_features": dom_feats,
                    "redirect_chain": redirect_chain,
                    "network_observation": {
                        "requests_inspected": req_counter["count"],
                        "external_domains_contacted": sorted(req_counter["external_destinations"])[:25],
                        "blocked_unsafe_requests": req_counter["blocked"][:10],
                    },
                    "behavioural_evidence": (
                        ["Rendered live DOM in isolated Playwright context (cross-origin iframe internals remain sandboxed)."]
                    ),
                }
            finally:
                try:
                    browser.close()
                except Exception:
                    pass
    except SSRFBlockedError:
        raise
    except Exception as e:
        return {
            "available": False,
            "analysis_mode": "static_html_fallback",
            "reason": f"Playwright inspection skipped: {e}",
        }

