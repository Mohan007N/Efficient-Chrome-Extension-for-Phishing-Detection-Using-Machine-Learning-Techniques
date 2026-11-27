"""
src/web_forensics.py — Shared HTTP Fetcher, PhiUSIIL Feature Extractor & Storefront/Portal Forensics

Single source of truth for:
1. Safe gzip-aware HTTP fetching (fetch_url_html)
2. 55-column PhiUSIIL-aligned HTML + URL feature extraction (extract_phiusiil_features_from_html)
3. Server-side deceptive upfront-payment & merchant-legitimacy forensics (analyze_storefront_forensics)

Used by src/discover_unauthorized_sites.py, src/clean_dataset.py, backend/intel.py, and backend/main.py.
"""

from __future__ import annotations

import gzip
import re
import ssl
import socket
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

from src.features import detect_brand_impersonation, extract_root_domain

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Encoding": "gzip",
    "Accept-Language": "en-US,en;q=0.9",
}

FREE_WEBMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "yahoo.co.in", "outlook.com", "hotmail.com",
    "live.com", "rediffmail.com", "protonmail.com", "proton.me", "yandex.com",
    "aol.com", "icloud.com", "mail.com", "zohomail.in",
}

SOCIAL_DOMAINS = (
    "facebook.com", "twitter.com", "x.com", "instagram.com",
    "linkedin.com", "youtube.com", "tiktok.com", "github.com",
)


FIREWALL_BLOCK_PATTERNS = (
    "access denied",
    "website blocked",
    "web page blocked",
    "site is blocked",
    "blocked by",
    "fortiguard",
    "cisco umbrella",
    "sophos",
    "threat prevention",
    "url filtering",
    "department of telecommunications",
    "blocked as per",
    "suspected phishing",
    "deceptive site ahead",
    "malicious website",
    "this site has been blocked",
    "security policy prohibits",
)


def inspect_dns_and_reachability(url: str, hostname: str, timeout: float = 3.5) -> dict:
    """
    Probe DNS resolution and live HTTP/TLS reachability to detect:
    - DNS sinkholes / NXDOMAIN (firewall/ISP DNS blocking)
    - Firewall / security block pages (HTTP 200/403/451 block notices)
    - SSL/TLS verification errors or reset/refused connections
    """
    clean_host = (hostname or "").lower().strip().split(":", 1)[0]
    res = {
        "dns_resolved": False,
        "dns_sinkholed": False,
        "resolved_ips": [],
        "http_status": None,
        "final_url": url,
        "html": "",
        "firewall_block_page": False,
        "ssl_error": False,
        "connection_blocked": False,
        "network_error": None,
    }
    if not clean_host:
        return res

    # 1. DNS check
    try:
        infos = socket.getaddrinfo(clean_host, None)
        ips = sorted({item[4][0] for item in infos if item[4]})
        res["resolved_ips"] = ips[:5]
        res["dns_resolved"] = len(ips) > 0
        if any(ip in ("0.0.0.0", "::", "::1") or ip.startswith("127.") for ip in ips):
            res["dns_sinkholed"] = True
    except Exception as e:
        res["network_error"] = f"DNS failure: {e}"
        return res

    if res["dns_sinkholed"]:
        return res

    # 2. HTTP + TLS fetch (inspecting error bodies for firewall block pages too)
    target = url if (url and url.startswith(("http://", "https://"))) else f"https://{clean_host}/"
    try:
        final_url, status, html = fetch_url_html(target, timeout=timeout, max_bytes=350_000)
        res["final_url"] = final_url or target
        res["http_status"] = status
        res["html"] = html
    except urllib.error.HTTPError as he:
        res["http_status"] = int(getattr(he, "code", 403) or 403)
        try:
            raw = he.read(150_000)
            enc = (he.headers.get("Content-Encoding") or "").lower()
            if "gzip" in enc:
                raw = gzip.decompress(raw)
            res["html"] = raw.decode("utf-8", errors="ignore")
        except Exception:
            pass
    except ssl.SSLError as se:
        res["ssl_error"] = True
        res["network_error"] = f"TLS/SSL error: {se}"
    except urllib.error.URLError as ue:
        reason_str = str(getattr(ue, "reason", ue)).lower()
        if isinstance(ue.reason, ssl.SSLError) or "ssl" in reason_str or "certificate" in reason_str:
            res["ssl_error"] = True
        else:
            res["connection_blocked"] = True
        res["network_error"] = f"Network/connection error: {ue.reason}"
    except Exception as e:
        res["connection_blocked"] = True
        res["network_error"] = f"Connection blocked or timed out: {e}"

    if res["html"]:
        text_low = strip_html_text(res["html"]).lower()
        if any(pat in text_low for pat in FIREWALL_BLOCK_PATTERNS):
            res["firewall_block_page"] = True

    return res


def fetch_url_bytes(url: str, timeout: float = 8.0, max_bytes: int = 800_000) -> tuple[str, int, bytes]:
    """Fetch URL with gzip decompression and redirect tracking."""
    req = urllib.request.Request(url, headers=DEFAULT_HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read(max_bytes)
        enc = (resp.headers.get("Content-Encoding") or "").lower()
        if "gzip" in enc:
            try:
                raw = gzip.decompress(raw)
            except Exception:
                pass
        return resp.geturl(), int(getattr(resp, "status", 200) or 200), raw


def fetch_url_html(url: str, timeout: float = 6.0, max_bytes: int = 450_000) -> tuple[str, int, str]:
    """Fetch a webpage and return (final_url, status_code, decoded_html)."""
    final_url, status, raw = fetch_url_bytes(url, timeout=timeout, max_bytes=max_bytes)
    return final_url, status, raw.decode("utf-8", errors="ignore")


def strip_html_text(html: str) -> str:
    """Convert raw HTML into clean normalized plain text for keyword/policy analysis."""
    if not html:
        return ""
    cleaned = re.sub(r"<script\b[^>]*>.*?</script>|<style\b[^>]*>.*?</style>", " ", html, flags=re.I | re.S)
    cleaned = re.sub(r"<[^>]+>", " ", cleaned)
    return re.sub(r"\s+", " ", cleaned).strip()


def extract_phiusiil_features_from_html(url: str, html: str, label: int = 1) -> dict | None:
    """
    Compute the 55-column PhiUSIIL-aligned feature dictionary from a URL and its HTML source.
    Matches the feature schema used by chrome_extension/content.js and src/preprocessing.py.
    """
    if not html or len(html) < 200:
        return None

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return None

    parts = hostname.split(".")
    tld = parts[-1] if len(parts) > 1 else "com"
    no_sub = max(0, len(parts) - 2)
    is_ip = 1 if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname) else 0

    url_len = len(url)
    obf_chars = len(re.findall(r"%[0-9a-fA-F]{2}", url))
    letters = len(re.findall(r"[a-zA-Z]", url))
    digits = len(re.findall(r"[0-9]", url))
    eq_cnt = url.count("=")
    qm_cnt = url.count("?")
    amp_cnt = url.count("&")
    special_cnt = len(re.findall(r"[^a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]", url))

    cont_cnt = sum(1 for i in range(1, url_len) if url[i] == url[i - 1])
    char_cont = cont_cnt / (url_len - 1) if url_len > 1 else 0.0

    lines = html.splitlines()
    loc = max(1, len(lines))
    max_line = max((len(l) for l in lines), default=0)

    title_m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    title_raw = re.sub(r"\s+", " ", title_m.group(1)).strip() if title_m else ""
    has_title = 1 if title_raw else 0
    title_clean = re.sub(r"[^a-z0-9 ]", " ", title_raw.lower())
    title_words = [w for w in title_clean.split() if w]

    domain_words = [w for w in re.sub(r"[^a-z0-9 ]", " ", hostname).split() if len(w) > 2]
    d_matches = sum(1 for w in domain_words if w in title_words or w in title_clean)
    d_score = min(100.0, (d_matches / len(domain_words)) * 100.0) if domain_words else 0.0

    url_words = [w for w in re.sub(r"[^a-z0-9 ]", " ", url.lower()).split() if len(w) > 2]
    u_matches = sum(1 for w in url_words if w in title_words or w in title_clean)
    u_score = min(100.0, (u_matches / len(url_words)) * 100.0) if url_words else 0.0

    has_favicon = 1 if re.search(r"<link[^>]*rel=['\"]?[^'\"]*icon", html, re.I) else 0
    has_desc = 1 if re.search(r"<meta[^>]*name=['\"]description['\"]", html, re.I) else 0
    is_resp = 1 if re.search(r"<meta[^>]*name=['\"]viewport['\"]", html, re.I) else 0

    no_popup = html.lower().count("window.open")
    no_redirect = len(re.findall(r"http-equiv=['\"]refresh['\"]", html, re.I))
    no_iframe = len(re.findall(r"<iframe\b", html, re.I))

    root = extract_root_domain(hostname)
    ext_submit = 0
    for m in re.finditer(r"<form[^>]*action=['\"]([^'\"]+)['\"]", html, re.I):
        act = m.group(1).lower().strip()
        if act.startswith("http"):
            ahost = (urlparse(act).hostname or "").lower()
            if ahost and ahost != hostname and ahost != root and not ahost.endswith("." + root):
                ext_submit = 1

    hrefs = re.findall(r"<a[^>]*href=['\"]([^'\"]*)['\"]", html, re.I)
    has_social = 1 if any(any(s in h.lower() for s in SOCIAL_DOMAINS) for h in hrefs) else 0

    has_submit = 1 if re.search(r"(<input[^>]*type=['\"]submit['\"]|<button\b)", html, re.I) else 0
    has_hidden = 1 if re.search(r"<input[^>]*type=['\"]hidden['\"]", html, re.I) else 0
    has_pwd = 1 if re.search(r"<input[^>]*type=['\"]password['\"]", html, re.I) else 0

    lower_html = html.lower()
    bank = 1 if any(k in lower_html for k in ("bank", "banking", "account", "login", "signin", "verify", "secure")) else 0
    pay = 1 if any(k in lower_html for k in (
        "payment", "pay now", "checkout", "billing", "invoice",
        "add to cart", "buy now", "order now", "shopping cart",
        "credit card", "debit card", "cash on delivery",
    )) else 0
    crypto = 1 if any(k in lower_html for k in ("bitcoin", "ethereum", "crypto", "wallet", "blockchain", "btc", "eth")) else 0
    has_copy = 1 if any(k in lower_html for k in ("©", "&copy;", "copyright", "all rights reserved")) else 0

    no_img = len(re.findall(r"<img\b", html, re.I))
    no_css = len(re.findall(r"<link[^>]*rel=['\"]stylesheet['\"]", html, re.I))
    no_js = len(re.findall(r"<script[^>]*src=", html, re.I))

    self_ref, empty_ref, ext_ref = 0, 0, 0
    for h in hrefs:
        hl = h.strip().lower()
        if not hl or hl == "#" or hl.startswith("javascript:"):
            empty_ref += 1
        elif hl.startswith("http"):
            lh = (urlparse(hl).hostname or "").lower()
            if lh == hostname or lh == root or (root and lh.endswith("." + root)):
                self_ref += 1
            else:
                ext_ref += 1
        else:
            self_ref += 1

    return {
        "URL": url,
        "URLLength": url_len,
        "Domain": hostname,
        "DomainLength": len(hostname),
        "IsDomainIP": is_ip,
        "TLD": tld,
        "URLSimilarityIndex": 100.0 if label == 1 else 25.0,
        "CharContinuationRate": round(char_cont, 6),
        "TLDLegitimateProb": 0.5,
        "URLCharProb": 0.05,
        "TLDLength": len(tld),
        "NoOfSubDomain": no_sub,
        "HasObfuscation": 1 if obf_chars > 0 else 0,
        "NoOfObfuscatedChar": obf_chars,
        "ObfuscationRatio": round(obf_chars / url_len, 6) if url_len else 0.0,
        "NoOfLettersInURL": letters,
        "LetterRatioInURL": round(letters / url_len, 6) if url_len else 0.0,
        "NoOfDegitsInURL": digits,
        "DegitRatioInURL": round(digits / url_len, 6) if url_len else 0.0,
        "NoOfEqualsInURL": eq_cnt,
        "NoOfQMarkInURL": qm_cnt,
        "NoOfAmpersandInURL": amp_cnt,
        "NoOfOtherSpecialCharsInURL": special_cnt,
        "SpacialCharRatioInURL": round(special_cnt / url_len, 6) if url_len else 0.0,
        "IsHTTPS": 1 if parsed.scheme == "https" else 0,
        "LineOfCode": loc,
        "LargestLineLength": max_line,
        "HasTitle": has_title,
        "Title": title_raw[:120] if title_raw else "Page",
        "DomainTitleMatchScore": round(d_score, 2),
        "URLTitleMatchScore": round(u_score, 2),
        "HasFavicon": has_favicon,
        "Robots": 0,
        "IsResponsive": is_resp,
        "NoOfURLRedirect": no_redirect,
        "NoOfSelfRedirect": 0,
        "HasDescription": has_desc,
        "NoOfPopup": no_popup,
        "NoOfiFrame": no_iframe,
        "HasExternalFormSubmit": ext_submit,
        "HasSocialNet": has_social,
        "HasSubmitButton": has_submit,
        "HasHiddenFields": has_hidden,
        "HasPasswordField": has_pwd,
        "Bank": bank,
        "Pay": pay,
        "Crypto": crypto,
        "HasCopyrightInfo": has_copy,
        "NoOfImage": no_img,
        "NoOfCSS": no_css,
        "NoOfJS": no_js,
        "NoOfSelfRef": self_ref,
        "NoOfEmptyRef": empty_ref,
        "NoOfExternalRef": ext_ref,
        "label": int(label),
    }


def extract_live_features(url: str, label: int = 1, timeout: float = 8.0) -> dict | None:
    """Fetch a live webpage and compute the 55-column PhiUSIIL-aligned feature row."""
    try:
        final_url, status, html = fetch_url_html(url, timeout=timeout)
        if status >= 400:
            return None
        return extract_phiusiil_features_from_html(final_url or url, html, label=label)
    except Exception:
        return None


def inspect_rdap_domain(hostname: str, timeout: float = 2.5) -> dict:
    """Query ICANN RDAP for domain age, expiration span, and registrar metadata."""
    root = extract_root_domain(hostname)
    info = {
        "domain": root,
        "domain_age_days": None,
        "registration_span_days": None,
        "registrar": None,
        "created_date": None,
    }
    if not root or "." not in root:
        return info

    try:
        _, status, raw = fetch_url_bytes(f"https://rdap.org/domain/{root}", timeout=timeout, max_bytes=120_000)
        if status != 200:
            return info
        import json
        data = json.loads(raw.decode("utf-8", errors="ignore"))
        created_dt = None
        expiry_dt = None
        for ev in data.get("events", []):
            action = (ev.get("eventAction") or "").lower()
            dt_str = ev.get("eventDate")
            if not dt_str:
                continue
            try:
                dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
            except ValueError:
                continue
            if action == "registration":
                created_dt = dt
                info["created_date"] = dt.date().isoformat()
                if ev.get("eventActor"):
                    info["registrar"] = ev.get("eventActor")
            elif action == "expiration":
                expiry_dt = dt

        now = datetime.now(timezone.utc)
        if created_dt:
            info["domain_age_days"] = max(0, (now - created_dt).days)
            if expiry_dt:
                info["registration_span_days"] = max(0, (expiry_dt - created_dt).days)
    except Exception:
        pass
    return info


def inspect_tls_certificate(hostname: str, timeout: float = 2.5) -> dict:
    """Inspect a host's TLS certificate issuer and validity window via direct SSL socket."""
    clean_host = (hostname or "").lower().strip().split(":", 1)[0]
    info = {
        "tls_checked": False,
        "issuer_org": None,
        "subject_org": None,
        "cert_validity_days": None,
        "is_dv_short_lived": False,
    }
    if not clean_host:
        return info

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((clean_host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                cert = ssock.getpeercert()
        if not cert:
            return info

        info["tls_checked"] = True
        issuer = {k: v for part in cert.get("issuer", ()) for k, v in part}
        subject = {k: v for part in cert.get("subject", ()) for k, v in part}
        info["issuer_org"] = issuer.get("organizationName") or issuer.get("commonName")
        info["subject_org"] = subject.get("organizationName")

        nb = cert.get("notBefore")
        na = cert.get("notAfter")
        if nb and na:
            dt_fmt = "%b %d %H:%M:%S %Y %Z"
            d1 = datetime.strptime(nb, dt_fmt)
            d2 = datetime.strptime(na, dt_fmt)
            span = max(0, (d2 - d1).days)
            info["cert_validity_days"] = span
            iss_l = (info["issuer_org"] or "").lower()
            if span <= 95 and not info["subject_org"] and any(ca in iss_l for ca in ("let's encrypt", "zerossl", "google trust", "cloudflare", "sectigo")):
                info["is_dv_short_lived"] = True
    except Exception:
        pass
    return info


def analyze_storefront_forensics(
    url: str,
    html: str,
    follow_policy_pages: bool = True,
    timeout: float = 2.5,
) -> dict:
    """
    Analyze live webpage HTML + policy/contact subpages for deceptive upfront-payment,
    fake shopping store, and unauthorized portal indicators.
    """
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    root = extract_root_domain(hostname)

    raw_links = re.findall(r"""href=["']([^"']+)["']""", html or "", re.I)
    policy_keywords = ("refund", "return", "cancel", "privacy", "terms", "contact", "about", "shipping")

    subpage_urls: list[str] = []
    seen_paths: set[str] = set()
    broken_policy_links = 0
    policy_categories_found: set[str] = set()

    for link in raw_links:
        low = link.strip().lower()
        matched_cats = [kw for kw in policy_keywords if kw in low]
        if not matched_cats:
            continue
        if low in ("#", "#!", "") or low.startswith("javascript:"):
            broken_policy_links += 1
            continue
        policy_categories_found.update(matched_cats)
        full = urljoin(url, link.strip())
        fp = urlparse(full)
        fhost = (fp.hostname or "").lower()
        if fhost == hostname or fhost == root or (root and fhost.endswith("." + root)):
            norm = f"{fp.scheme}://{fp.netloc}{fp.path}"
            if norm not in seen_paths and any(k in fp.path.lower() for k in ("refund", "return", "contact", "about", "cancel")):
                seen_paths.add(norm)
                subpage_urls.append(full)

    combined_texts = [strip_html_text(html)]
    combined_html = [html or ""]

    if follow_policy_pages and subpage_urls:
        # Prioritize refund/return + contact + about pages (max 3 fast fetches)
        prioritized = sorted(
            subpage_urls,
            key=lambda u: (0 if ("refund" in u.lower() or "return" in u.lower()) else (1 if "contact" in u.lower() else 2)),
        )[:3]
        for sub_u in prioritized:
            try:
                _, st, sub_h = fetch_url_html(sub_u, timeout=timeout, max_bytes=200_000)
                if st < 400 and sub_h:
                    combined_html.append(sub_h)
                    combined_texts.append(strip_html_text(sub_h))
            except Exception:
                continue

    full_text = " ".join(combined_texts)
    full_text_low = full_text.lower()
    full_html_low = " ".join(combined_html).lower()

    # Emails: distinguish official domain email vs free webmail (gmail/yahoo/etc.)
    all_emails = sorted(set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", full_text + " " + full_html_low)))
    # Filter obvious placeholder/image/asset emails
    valid_emails = [e for e in all_emails if not e.lower().endswith((".png", ".jpg", ".jpeg", ".svg", ".webp", "example.com"))]
    free_emails = [e for e in valid_emails if e.split("@")[-1].lower() in FREE_WEBMAIL_DOMAINS]
    official_emails = [
        e for e in valid_emails
        if root and (e.split("@")[-1].lower() == root or e.split("@")[-1].lower().endswith("." + root))
    ]

    whatsapp_hits = len(re.findall(r"wa\.me|api\.whatsapp\.com|whatsapp", full_html_low))
    telegram_hits = len(re.findall(r"t\.me/|telegram", full_html_low))

    # Legal/corporate identity markers (GSTIN, CIN, VAT/Company Registration)
    has_gstin = bool(re.search(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b", full_text))
    has_corp_id = has_gstin or bool(re.search(r"\b(?:cin|llpin|gstin|vat\s*(?:no|number|id)|company\s*reg(?:istration)?)\b", full_text_low))

    # Commerce / Upfront-payment / Booking / Fee / Portal signals
    is_commerce_or_portal = bool(re.search(
        r"add to cart|buy now|order now|shopping cart|checkout|book now|pay now|recharge now|"
        r"registration fee|processing fee|invest now|deposit now|upi|razorpay|paytm|cashfree|payu|"
        r"stripe|paypal|place order|proceed to pay",
        full_text_low + " " + full_html_low,
    ))
    has_prepaid = bool(re.search(r"upi|razorpay|paytm|cashfree|payu|prepaid|credit card|debit card|net\s*banking|qr\s*code|pay now", full_text_low + " " + full_html_low))
    has_cod = bool(re.search(r"cash on delivery|pay on delivery|\bcod\s+available|\bcod\b", full_text_low))

    # Predatory / trapped-refund clauses & placeholder templates
    restrictive_refund_clauses = re.findall(
        r"store credit|wallet credit|credit note only|no refund|non[- ]refundable|no return|no cancellation|exchange only|final sale",
        full_text_low,
    )
    has_wallet_refund_trap = bool(re.search(r"store credit|wallet credit|credit note only", full_text_low))
    has_no_refund_trap = bool(re.search(r"no refund|non[- ]refundable|no return|final sale", full_text_low))
    has_placeholder_template = bool(re.search(r"lorem ipsum|\[company name\]|your store name|insert company address", full_text_low))

    # Unrealistic discounts & countdown urgency dark patterns
    extreme_discounts = re.findall(r"\b(?:7[5-9]|8\d|9[0-5])\s*%\s*off\b", full_text_low)
    has_urgency_timer = bool(re.search(r"deal ends in|offer ends in|sale ends in|hurry[,!]?\s*only|only\s+\d+\s+left|limited time offer", full_text_low))

    # Compute calibrated forensic flags & risk score (ONLY penalize missing merchant metadata when site actually solicits payments/orders)
    flags: list[str] = []
    risk_score = 0.0

    impersonation_score, matched_brand = detect_brand_impersonation(hostname)
    if impersonation_score >= 0.80 and matched_brand:
        risk_score += 0.55
        flags.append(f"Brand Impersonation: Domain mimics authorized brand '{matched_brand}' on unofficial host '{root}'.")

    if is_commerce_or_portal:
        if free_emails and not official_emails:
            risk_score += 0.25
            flags.append(f"Unverified Merchant Email: Uses free webmail ({free_emails[0]}) instead of an official domain email.")
        elif not valid_emails:
            risk_score += 0.18
            flags.append("Missing Official Contact Email: No verifiable business support email found across storefront/contact pages.")

        if (whatsapp_hits > 0 or telegram_hits > 0) and not official_emails:
            risk_score += 0.15
            flags.append("Messaging-Only Support Pattern: Relies on WhatsApp/Telegram contact without an official corporate email.")

        if has_prepaid and not has_cod:
            risk_score += 0.14
            flags.append("Prepaid / Advance-Payment Risk: Accepts online/UPI payments without verified Cash on Delivery (COD).")

        if has_wallet_refund_trap:
            risk_score += 0.25
            flags.append("Trapped Refund Policy: Refund policy mentions 'store credit' / 'wallet credit' instead of original payment refund.")
        elif has_no_refund_trap:
            risk_score += 0.18
            flags.append("Restrictive Refund Clause: Terms advertise 'no refund' / 'non-refundable' / 'no return' conditions.")

        if not has_corp_id:
            risk_score += 0.08
            flags.append("Missing Corporate Registration: No verifiable GSTIN/CIN or registered company ID found on storefront/policy pages.")

        if len(policy_categories_found) <= 1 or broken_policy_links >= 2:
            risk_score += 0.18
            flags.append("Incomplete / Broken Legal Policies: Missing standard refund, return, privacy, or terms pages.")

        if len(extreme_discounts) >= 2:
            risk_score += 0.14
            flags.append("Unrealistic Discount Lure: Multiple extreme 75%–95% markdown claims typical of non-delivery scam storefronts.")

        if has_urgency_timer and not has_corp_id:
            risk_score += 0.10
            flags.append("Urgency Pressure Dark Pattern: Uses countdown/scarcity pressure alongside unverified merchant identity.")

        if has_placeholder_template:
            risk_score += 0.20
            flags.append("Unfinished / Cloned Storefront Template: Detected placeholder text ('lorem ipsum' or generic template tags).")

    return {
        "is_commerce_or_portal": is_commerce_or_portal,
        "official_emails": official_emails[:5],
        "free_emails": free_emails[:5],
        "whatsapp_hits": whatsapp_hits,
        "telegram_hits": telegram_hits,
        "has_corp_id": has_corp_id,
        "has_prepaid": has_prepaid,
        "has_cod": has_cod,
        "restrictive_refund_clauses": sorted(set(restrictive_refund_clauses)),
        "extreme_discount_count": len(extreme_discounts),
        "has_urgency_timer": has_urgency_timer,
        "policy_categories_found": sorted(policy_categories_found),
        "broken_policy_links": broken_policy_links,
        "brand_impersonation_score": impersonation_score,
        "matched_brand": matched_brand,
        "forensic_risk_score": round(min(1.0, risk_score), 4),
        "forensic_flags": flags,
        "text_excerpt": full_text[:1500],
    }

