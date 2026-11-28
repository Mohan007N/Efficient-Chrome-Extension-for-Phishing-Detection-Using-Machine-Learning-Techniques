"""
src/dom_features.py — Dedicated DOM & HTML Behaviour Feature Extraction Pipeline (v3.0)

Extracts structured webpage behaviour signals identically from:
1. Static HTML documents (BeautifulSoup parser — never executes JavaScript)
2. Live browser DOM telemetry payloads sent by chrome_extension/content.js

Privacy & Modeling Rules:
- Never reads or stores password values, form input values, cookies, or auth tokens.
- Cross-origin iframe internals are inaccessible to content scripts and static HTML
  parsers; uninspected cross-origin iframes are explicitly counted and disclosed.
- Static HTML analysis is never misrepresented as complete runtime JS observation.
"""

from __future__ import annotations

import hashlib
import math
import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup
import pandas as pd

from src.features import PROTECTED_BRANDS, detect_brand_impersonation, extract_root_domain, is_hosted_user_content_subdomain

DOM_FEATURE_VERSION = "3.0.0"

# Features passed to Model 2 (DOM Behaviour Classifier)
DOM_FEATURE_COLUMNS: list[str] = [
    # Group A: Login & Credential Features
    "num_password_fields",
    "num_username_email_inputs",
    "num_login_forms",
    "has_external_form_action",
    "num_cross_domain_forms",
    "num_hidden_credential_inputs",
    "suspicious_login_indicators",
    "brand_domain_mismatch",
    # Group B: Form & Payment Features
    "total_forms",
    "external_forms_count",
    "has_post_form",
    "num_sensitive_inputs",
    "num_payment_inputs",
    "has_suspicious_payment_dest",
    "has_prepaid_without_cod",
    "has_restrictive_refund_terms",
    # Group C: Advertisement, Redirect & Deceptive Behaviour
    "num_iframes",
    "num_hidden_iframes",
    "num_external_scripts",
    "popup_trigger_count",
    "fake_download_button_count",
    "suspicious_link_ratio",
    "meta_refresh_redirects",
    "js_redirect_indicators",
    "misleading_button_count",
    "external_link_ratio",
    "notification_prompt_requested",
    # Group D: JavaScript & Webpage Architecture
    "inline_script_count",
    "suspicious_inline_js_count",
    "obfuscated_js_score",
    "dynamic_dom_mutation_count",
    "html_line_count",
    "has_title",
    "domain_title_match_score",
    "has_copyright_notice",
    "has_official_contact_cue",
]

# Observability & transport metadata kept separate from DOM classifier inputs
DOM_OBSERVABILITY_COLUMNS: list[str] = [
    "is_https",
    "mixed_content_count",
    "cross_origin_iframes_uninspected",
]

_USERNAME_PATTERNS = re.compile(r"(user|email|login|account|phone|mobile|member|id)", re.I)
_SENSITIVE_PATTERNS = re.compile(r"(card|cvv|cvc|ssn|pin|otp|routing|iban|aadhaar|pan|passport|password|passwd)", re.I)
_PAYMENT_PATTERNS = re.compile(r"(card|cvv|cvc|expiry|billing|upi|razorpay|paytm|cashfree|stripe|paypal|checkout|pay_now)", re.I)
_FAKE_DOWNLOAD_PATTERNS = re.compile(r"(download\s+now|free\s+download|start\s+download|click\s+to\s+download|update\s+flash|codec\s+update|apk\s+download)", re.I)
_MISLEADING_CTA_PATTERNS = re.compile(r"(claim\s+now|verify\s+immediately|urgent\s+action|account\s+suspended|deal\s+ends\s+in|limited\s+time\s+only|only\s+\d+\s+left|congratulations\s+you\s+won)", re.I)
_RESTRICTIVE_REFUND_PATTERNS = re.compile(r"(store\s+credit|wallet\s+credit|credit\s+note\s+only|no\s+refund|non[- ]refundable|no\s+return|final\s+sale)", re.I)
_PREPAID_PATTERNS = re.compile(r"(upi|razorpay|paytm|cashfree|payu|prepaid|qr\s*code|pay\s+now|credit\s+card|debit\s+card)", re.I)
_COD_PATTERNS = re.compile(r"(cash\s+on\s+delivery|pay\s+on\s+delivery|\bcod\s+available\b)", re.I)


def compute_content_sha256(html: str) -> str:
    """Compute SHA-256 content hash for HTML deduplication and dataset provenance."""
    return hashlib.sha256((html or "").encode("utf-8", errors="ignore")).hexdigest()


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _safe_soup(html: str) -> BeautifulSoup:
    try:
        return BeautifulSoup(html, "lxml")
    except Exception:
        return BeautifulSoup(html, "html.parser")


def extract_dom_features_from_html(
    url: str,
    html: str,
    analysis_mode: str = "static_html",
) -> dict:
    """
    Parse raw HTML statically (no script execution) and return standardized DOM features,
    observability counts, analysis_mode, and explicit unavailability disclosures.
    """
    parsed = urlparse(url or "")
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    root = extract_root_domain(host)
    is_https = 1 if scheme == "https" else 0
    user_hosted = is_hosted_user_content_subdomain(host)

    if not html or not html.strip():
        empty = {col: 0 for col in DOM_FEATURE_COLUMNS + DOM_OBSERVABILITY_COLUMNS}
        empty["analysis_mode"] = "unavailable"
        empty["unavailable_signals"] = [
            "html_source", "dom_forms", "scripts", "iframes",
            "runtime_js_behavior", "redirect_chain", "cert_details",
        ]
        return empty

    soup_full = _safe_soup(html)
    html_lower = html.lower()
    lines = html.splitlines()

    # Title & domain-title alignment (ignore 'www.' prefix cleanly)
    title_tag = soup_full.find("title")
    title_raw = re.sub(r"\s+", " ", title_tag.get_text(" ", strip=True)) if title_tag else ""
    has_title = 1 if title_raw else 0
    title_clean = re.sub(r"[^a-z0-9 ]", " ", title_raw.lower())
    title_compact = title_clean.replace(" ", "")
    title_words = [w for w in title_clean.split() if w]
    host_no_www = host[4:] if host.startswith("www.") else host
    domain_words = [w for w in re.sub(r"[^a-z0-9 ]", " ", host_no_www).split() if len(w) > 2]
    d_matches = sum(1 for w in domain_words if w in title_words or w in title_clean or w in title_compact)
    domain_title_match_score = round(min(100.0, (d_matches / len(domain_words)) * 100.0), 2) if domain_words else 0.0

    # Body text extracted safely without stripping elements from `soup_full`
    visible_chunks: list[str] = []
    for txt_node in soup_full.find_all(string=True):
        parent_name = getattr(getattr(txt_node, "parent", None), "name", "")
        if parent_name not in ("script", "style", "noscript"):
            s_node = str(txt_node).strip()
            if s_node:
                visible_chunks.append(s_node)
    body_text = re.sub(r"\s+", " ", " ".join(visible_chunks)).strip()
    body_lower = body_text.lower()

    # Claimed brand mismatch: check if title names a protected brand not matching official root
    imp_score, matched_brand = detect_brand_impersonation(host)
    brand_domain_mismatch = 1 if (imp_score >= 0.80 and matched_brand) else 0
    if not brand_domain_mismatch and title_raw:
        for brand, official_roots in PROTECTED_BRANDS.items():
            is_official = (not user_hosted) and (root in official_roots or any(host.endswith("." + off) for off in official_roots))
            if len(brand) >= 6 and brand in title_clean and not is_official:
                if re.search(r"\b(login|sign\s*in|verify|account|official|checkout|support|kyc)\b", title_clean):
                    brand_domain_mismatch = 1
                    break

    # Group A & B: Forms, credentials, and payment inputs (inspect metadata names/types only, never values)
    forms = soup_full.find_all("form")
    total_forms = len(forms)
    num_password_fields = len(soup_full.find_all("input", attrs={"type": re.compile(r"^password$", re.I)}))
    num_username_email_inputs = 0
    num_sensitive_inputs = 0
    num_payment_inputs = 0
    num_login_forms = 0
    external_forms_count = 0
    num_cross_domain_forms = 0
    num_hidden_credential_inputs = 0
    has_post_form = 0
    has_suspicious_payment_dest = 0

    for inp in soup_full.find_all(["input", "select", "textarea"]):
        itype = str(inp.get("type") or "").lower()
        meta_text = " ".join(
            str(inp.get(attr) or "") for attr in ("name", "id", "placeholder", "autocomplete", "aria-label")
        )
        if itype in ("email", "text", "tel") and _USERNAME_PATTERNS.search(meta_text):
            num_username_email_inputs += 1
        if _SENSITIVE_PATTERNS.search(meta_text) or itype == "password":
            num_sensitive_inputs += 1
        if _PAYMENT_PATTERNS.search(meta_text):
            num_payment_inputs += 1

    for form in forms:
        method = str(form.get("method") or "get").lower()
        if method == "post":
            has_post_form = 1
        action = str(form.get("action") or "").strip()
        is_ext_form = False
        if action.startswith(("http://", "https://")):
            ahost = (urlparse(action).hostname or "").lower()
            aroot = extract_root_domain(ahost)
            if ahost and aroot != root and ahost != host:
                is_ext_form = True
        if is_ext_form:
            external_forms_count += 1
            num_cross_domain_forms += 1

        f_pwds = form.find_all("input", attrs={"type": re.compile(r"^password$", re.I)})
        f_hidden = form.find_all("input", attrs={"type": re.compile(r"^hidden$", re.I)})
        f_text = " ".join(str(x.get("name") or "") + " " + str(x.get("placeholder") or "") for x in form.find_all("input"))
        is_login_f = bool(f_pwds) or bool(_USERNAME_PATTERNS.search(f_text) and form.find(["button", "input"]))
        if is_login_f:
            num_login_forms += 1
            num_hidden_credential_inputs += len(f_hidden)
        if is_ext_form and _PAYMENT_PATTERNS.search(f_text + " " + action):
            has_suspicious_payment_dest = 1

    has_external_form_action = 1 if external_forms_count > 0 else 0
    suspicious_login_indicators = int(
        (num_password_fields > 0 and is_https == 0)
        + (num_password_fields > 0 and has_external_form_action == 1)
        + (num_login_forms > 0 and brand_domain_mismatch == 1)
    )

    is_commerce = bool(_PREPAID_PATTERNS.search(body_lower + " " + html_lower) or re.search(r"add\s+to\s+cart|buy\s+now|checkout|shopping\s+cart", body_lower))
    has_prepaid_without_cod = 1 if (is_commerce and _PREPAID_PATTERNS.search(body_lower) and not _COD_PATTERNS.search(body_lower)) else 0
    has_restrictive_refund_terms = 1 if _RESTRICTIVE_REFUND_PATTERNS.search(body_lower) else 0

    # Group C: Iframes, scripts, links, popups, redirects & deceptive CTAs
    iframes = soup_full.find_all("iframe")
    num_iframes = len(iframes)
    num_hidden_iframes = 0
    cross_origin_iframes_uninspected = 0
    mixed_content_count = 0

    for ifr in iframes:
        style = str(ifr.get("style") or "").lower()
        w = str(ifr.get("width") or "").strip()
        h = str(ifr.get("height") or "").strip()
        if "display:none" in style.replace(" ", "") or "visibility:hidden" in style.replace(" ", "") or w in ("0", "1", "1px") or h in ("0", "1", "1px"):
            num_hidden_iframes += 1
        src = str(ifr.get("src") or "").strip()
        if src.startswith("http://") and is_https:
            mixed_content_count += 1
        if src.startswith(("http://", "https://")):
            ihost = (urlparse(src).hostname or "").lower()
            if extract_root_domain(ihost) != root:
                cross_origin_iframes_uninspected += 1

    scripts = soup_full.find_all("script")
    num_external_scripts = 0
    inline_script_count = 0
    suspicious_inline_js_count = 0
    obfuscated_js_score = 0.0
    dynamic_dom_mutation_count = 0
    popup_trigger_count = 0
    js_redirect_indicators = 0
    notification_prompt_requested = 0

    for sc in scripts:
        src = str(sc.get("src") or "").strip()
        if src:
            if src.startswith("http://") and is_https:
                mixed_content_count += 1
            if src.startswith(("http://", "https://")) or src.startswith("//"):
                shost = (urlparse("https:" + src if src.startswith("//") else src).hostname or "").lower()
                if shost and extract_root_domain(shost) != root:
                    num_external_scripts += 1
        else:
            code = sc.string or sc.get_text() or ""
            if code.strip():
                inline_script_count += 1
                susp_hits = len(re.findall(r"\b(?:eval|Function|atob|unescape|fromCharCode|document\.write)\s*\(", code))
                suspicious_inline_js_count += susp_hits
                if len(code) > 250:
                    ent = _shannon_entropy(code[:2000])
                    hex_esc = len(re.findall(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}", code))
                    if ent > 5.2 or hex_esc >= 8:
                        obfuscated_js_score = min(1.0, max(obfuscated_js_score, 0.5 + min(0.5, hex_esc / 30.0)))
                dynamic_dom_mutation_count += len(re.findall(r"createElement\s*\(\s*['\"](?:script|iframe)['\"]|innerHTML\s*=|insertAdjacentHTML", code))
                popup_trigger_count += code.lower().count("window.open(")
                js_redirect_indicators += len(re.findall(r"(?:window|document|top)\.location(?:\.href)?\s*=|location\.replace\(", code))
                if "Notification.requestPermission" in code:
                    notification_prompt_requested = 1

    if is_https:
        for img in soup_full.find_all("img", src=True):
            if str(img["src"]).strip().lower().startswith("http://"):
                mixed_content_count += 1

    meta_refresh_redirects = len(soup_full.find_all("meta", attrs={"http-equiv": re.compile(r"refresh", re.I)}))

    links = soup_full.find_all("a", href=True)
    total_links = len(links)
    susp_links = 0
    ext_links = 0
    fake_download_button_count = 0
    for a in links:
        href = str(a.get("href") or "").strip()
        hlow = href.lower()
        txt = a.get_text(" ", strip=True)
        if not hlow or hlow in ("#", "#!") or hlow.startswith("javascript:"):
            susp_links += 1
        elif hlow.startswith(("http://", "https://")):
            lhost = (urlparse(href).hostname or "").lower()
            if lhost and extract_root_domain(lhost) != root:
                ext_links += 1
        if _FAKE_DOWNLOAD_PATTERNS.search(txt):
            if hlow in ("#", "") or hlow.endswith((".exe", ".msi", ".bat", ".scr", ".zip", ".apk")) or (hlow.startswith("http") and extract_root_domain((urlparse(href).hostname or "").lower()) != root):
                fake_download_button_count += 1

    for btn in soup_full.find_all(["button", "input"]):
        btxt = (btn.get_text(" ", strip=True) if btn.name == "button" else str(btn.get("value") or ""))
        if _FAKE_DOWNLOAD_PATTERNS.search(btxt):
            fake_download_button_count += 1

    misleading_button_count = len(_MISLEADING_CTA_PATTERNS.findall(body_text))
    suspicious_link_ratio = round(susp_links / max(1, total_links), 4)
    external_link_ratio = round(ext_links / max(1, total_links), 4)

    has_copyright_notice = 1 if any(k in html_lower[:60_000] for k in ("©", "&copy;", "copyright", "all rights reserved")) else 0
    email_search_text = body_lower[:40_000]
    emails = re.findall(r"\b[a-z0-9._%+-]{1,40}@([a-z0-9-]{1,40}(?:\.[a-z0-9-]{1,24}){1,4})\b", email_search_text)
    has_official_contact_cue = 1 if any(root and (em == root or em.endswith("." + root)) for em in emails) else 0

    unavailable = ["cert_details"]
    if analysis_mode == "static_html":
        unavailable.append("runtime_js_behavior (static HTML only)")
    if cross_origin_iframes_uninspected > 0:
        unavailable.append(f"cross_origin_iframe_dom ({cross_origin_iframes_uninspected} frames)")

    return {
        "num_password_fields": int(num_password_fields),
        "num_username_email_inputs": int(num_username_email_inputs),
        "num_login_forms": int(num_login_forms),
        "has_external_form_action": int(has_external_form_action),
        "num_cross_domain_forms": int(num_cross_domain_forms),
        "num_hidden_credential_inputs": int(num_hidden_credential_inputs),
        "suspicious_login_indicators": int(suspicious_login_indicators),
        "brand_domain_mismatch": int(brand_domain_mismatch),
        "total_forms": int(total_forms),
        "external_forms_count": int(external_forms_count),
        "has_post_form": int(has_post_form),
        "num_sensitive_inputs": int(num_sensitive_inputs),
        "num_payment_inputs": int(num_payment_inputs),
        "has_suspicious_payment_dest": int(has_suspicious_payment_dest),
        "has_prepaid_without_cod": int(has_prepaid_without_cod),
        "has_restrictive_refund_terms": int(has_restrictive_refund_terms),
        "num_iframes": int(num_iframes),
        "num_hidden_iframes": int(num_hidden_iframes),
        "num_external_scripts": int(num_external_scripts),
        "popup_trigger_count": int(popup_trigger_count),
        "fake_download_button_count": int(fake_download_button_count),
        "suspicious_link_ratio": float(suspicious_link_ratio),
        "meta_refresh_redirects": int(meta_refresh_redirects),
        "js_redirect_indicators": int(js_redirect_indicators),
        "misleading_button_count": int(misleading_button_count),
        "external_link_ratio": float(external_link_ratio),
        "notification_prompt_requested": int(notification_prompt_requested),
        "inline_script_count": int(inline_script_count),
        "suspicious_inline_js_count": int(suspicious_inline_js_count),
        "obfuscated_js_score": round(float(obfuscated_js_score), 4),
        "dynamic_dom_mutation_count": int(dynamic_dom_mutation_count),
        "html_line_count": int(len(lines)),
        "has_title": int(has_title),
        "domain_title_match_score": float(domain_title_match_score),
        "has_copyright_notice": int(has_copyright_notice),
        "has_official_contact_cue": int(has_official_contact_cue),
        "is_https": int(is_https),
        "mixed_content_count": int(mixed_content_count),
        "cross_origin_iframes_uninspected": int(cross_origin_iframes_uninspected),
        "analysis_mode": analysis_mode,
        "unavailable_signals": unavailable,
    }


def validate_dom_feature_schema(features_or_df: dict | pd.DataFrame, expected_columns: list[str] | None = None) -> list[str]:
    cols = expected_columns or DOM_FEATURE_COLUMNS
    if isinstance(features_or_df, pd.DataFrame):
        missing = [c for c in cols if c not in features_or_df.columns]
        if missing:
            raise ValueError(f"DOM feature DataFrame missing columns: {missing}")
        if list(features_or_df[cols].columns) != list(cols):
            raise ValueError("DOM feature column order mismatch.")
        return cols
    missing = [c for c in cols if c not in features_or_df]
    if missing:
        raise ValueError(f"DOM feature dict missing columns: {missing}")
    return cols


_STRUCTURAL_OBSERVATION_KEYS = (
    "html_line_count",
    "has_title",
    "total_forms",
    "num_password_fields",
    "num_username_email_inputs",
    "num_payment_inputs",
    "num_sensitive_inputs",
    "num_iframes",
    "num_external_scripts",
    "inline_script_count",
    "fake_download_button_count",
    "meta_refresh_redirects",
    "js_redirect_indicators",
    "popup_trigger_count",
    "misleading_button_count",
    "has_copyright_notice",
    "has_official_contact_cue",
    "domain_title_match_score",
    "external_link_ratio",
    "suspicious_link_ratio",
)


def has_meaningful_dom_observation(payload: dict | None) -> bool:
    """
    Return True only when a DOM payload carries genuine observed structural indicators
    (preventing empty `dom_features={}` dicts from spoofing an observed webpage).
    """
    if not isinstance(payload, dict) or not payload:
        return False
    return any(float(payload.get(k) or 0.0) > 0.0 for k in _STRUCTURAL_OBSERVATION_KEYS)


def normalize_dom_feature_dict(payload: dict, url: str = "") -> dict:
    """
    Normalize a DOM payload (either rich dom_features or legacy content.js fields)
    into the exact DOM_FEATURE_COLUMNS + DOM_OBSERVABILITY_COLUMNS schema without forcing
    a fake HTTPS=1 default when transport info is missing or HTTP.
    """
    p = payload or {}
    parsed = urlparse(url or str(p.get("url", "")))
    scheme = (parsed.scheme or "").lower()
    raw_https = p.get("is_https")
    if raw_https is None:
        raw_https = p.get("IsHTTPS")
    if scheme == "https":
        is_https: int | None = 1
    elif scheme == "http":
        is_https = 0
    elif raw_https is not None:
        is_https = int(bool(raw_https))
    else:
        is_https = None

    has_pwd = int(p.get("HasPasswordField", 0) or 0)
    ext_submit = int(p.get("HasExternalFormSubmit", 0) or 0)
    has_hidden = int(p.get("HasHiddenFields", 0) or 0)
    n_self = int(p.get("NoOfSelfRef", 0) or 0)
    n_empty = int(p.get("NoOfEmptyRef", 0) or 0)
    n_ext = int(p.get("NoOfExternalRef", 0) or 0)
    tot_links = max(1, n_self + n_empty + n_ext)

    out = {
        "num_password_fields": int(p.get("num_password_fields", has_pwd)),
        "num_username_email_inputs": int(p.get("num_username_email_inputs", 0)),
        "num_login_forms": int(p.get("num_login_forms", has_pwd)),
        "has_external_form_action": int(p.get("has_external_form_action", ext_submit)),
        "num_cross_domain_forms": int(p.get("num_cross_domain_forms", ext_submit)),
        "num_hidden_credential_inputs": int(p.get("num_hidden_credential_inputs", has_hidden if has_pwd else 0)),
        "suspicious_login_indicators": int(
            p.get(
                "suspicious_login_indicators",
                (1 if (has_pwd and is_https == 0) else 0) + (1 if (has_pwd and ext_submit) else 0),
            )
        ),
        "brand_domain_mismatch": int(p.get("brand_domain_mismatch", 0)),
        "total_forms": int(p.get("total_forms", max(has_pwd, int(p.get("HasSubmitButton", 0) or 0)))),
        "external_forms_count": int(p.get("external_forms_count", ext_submit)),
        "has_post_form": int(p.get("has_post_form", has_pwd)),
        "num_sensitive_inputs": int(p.get("num_sensitive_inputs", has_pwd)),
        "num_payment_inputs": int(p.get("num_payment_inputs", int(p.get("Pay", 0) or 0))),
        "has_suspicious_payment_dest": int(p.get("has_suspicious_payment_dest", 1 if (ext_submit and int(p.get("Pay", 0) or 0)) else 0)),
        "has_prepaid_without_cod": int(p.get("has_prepaid_without_cod", 0)),
        "has_restrictive_refund_terms": int(p.get("has_restrictive_refund_terms", 0)),
        "num_iframes": int(p.get("num_iframes", p.get("NoOfiFrame", 0) or 0)),
        "num_hidden_iframes": int(p.get("num_hidden_iframes", 0)),
        "num_external_scripts": int(p.get("num_external_scripts", p.get("NoOfJS", 0) or 0)),
        "popup_trigger_count": int(p.get("popup_trigger_count", p.get("NoOfPopup", 0) or 0)),
        "fake_download_button_count": int(p.get("fake_download_button_count", 0)),
        "suspicious_link_ratio": float(p.get("suspicious_link_ratio", round(n_empty / tot_links, 4))),
        "meta_refresh_redirects": int(p.get("meta_refresh_redirects", p.get("NoOfURLRedirect", 0) or 0)),
        "js_redirect_indicators": int(p.get("js_redirect_indicators", 0)),
        "misleading_button_count": int(p.get("misleading_button_count", 0)),
        "external_link_ratio": float(p.get("external_link_ratio", round(n_ext / tot_links, 4))),
        "notification_prompt_requested": int(p.get("notification_prompt_requested", 0)),
        "inline_script_count": int(p.get("inline_script_count", 0)),
        "suspicious_inline_js_count": int(p.get("suspicious_inline_js_count", 0)),
        "obfuscated_js_score": float(p.get("obfuscated_js_score", 0.0)),
        "dynamic_dom_mutation_count": int(p.get("dynamic_dom_mutation_count", 0)),
        "html_line_count": int(p.get("html_line_count", p.get("LineOfCode", 0) or 0)),
        "has_title": int(p.get("has_title", p.get("HasTitle", 0) or 0)),
        "domain_title_match_score": float(p.get("domain_title_match_score", p.get("DomainTitleMatchScore", 0.0) or 0.0)),
        "has_copyright_notice": int(p.get("has_copyright_notice", p.get("HasCopyrightInfo", 0) or 0)),
        "has_official_contact_cue": int(p.get("has_official_contact_cue", 0)),
        "is_https": is_https,
        "mixed_content_count": int(p.get("mixed_content_count", 0)),
        "cross_origin_iframes_uninspected": int(p.get("cross_origin_iframes_uninspected", 0)),
        "analysis_mode": str(p.get("analysis_mode") or "extension_dom"),
        "unavailable_signals": list(p.get("unavailable_signals", [])),
    }
    return out


def evaluate_credential_and_payment_risk(url: str, dom_feats: dict, brand_info: dict | None = None) -> dict:
    """
    Model 4: Credential & Payment Risk Detector.
    Evaluates password collection, cross-domain credential/payment destinations,
    unencrypted login forms, and upfront-payment scam signals without flagging
    standard HTTPS first-party login/checkout pages.
    """
    d = normalize_dom_feature_dict(dom_feats, url=url)
    b = brand_info or {}
    scheme = (urlparse(url or "").scheme or "").lower()
    is_http_explicit = (scheme == "http") or (d.get("is_https") == 0)
    is_https = not is_http_explicit
    has_login = d["num_password_fields"] > 0 or d["num_login_forms"] > 0
    has_payment = d["num_payment_inputs"] > 0 or d["has_prepaid_without_cod"] > 0 or d["has_suspicious_payment_dest"] > 0

    cred_evidence: list[str] = []
    cred_score = 0.0
    if has_login:
        if not is_https:
            cred_score += 0.45
            cred_evidence.append("Login or password form is served over unencrypted HTTP.")
        if d["has_external_form_action"]:
            cred_score += 0.55
            cred_evidence.append("Credential form submits to an external cross-domain destination.")
        if d["brand_domain_mismatch"] or float(b.get("brand_similarity_score", 0.0)) >= 0.80:
            cred_score += 0.40
            cred_evidence.append("Login page displays brand cues inconsistent with the actual root domain.")
        if d["num_hidden_credential_inputs"] >= 3 and d["has_external_form_action"]:
            cred_score += 0.15
            cred_evidence.append("Credential form contains multiple hidden fields with external submission.")

    pay_evidence: list[str] = []
    pay_score = 0.0
    if has_payment or d["has_restrictive_refund_terms"]:
        if not is_https:
            pay_score += 0.45
            pay_evidence.append("Payment or checkout inputs appear on an unencrypted HTTP connection.")
        if d["has_suspicious_payment_dest"]:
            pay_score += 0.50
            pay_evidence.append("Payment form targets an unverified external destination domain.")
        if d["has_restrictive_refund_terms"] and not d["has_official_contact_cue"]:
            pay_score += 0.35
            pay_evidence.append("Checkout/commerce site pairs restrictive refund/store-credit clauses with missing official domain email.")
        if d["has_prepaid_without_cod"] and d["suspicious_link_ratio"] >= 0.15:
            pay_score += 0.25
            pay_evidence.append("Prepaid-only payment signals alongside broken or empty navigation links.")
        if d["brand_domain_mismatch"] or float(b.get("brand_similarity_score", 0.0)) >= 0.80:
            pay_score += 0.35
            pay_evidence.append("Payment interface appears on a lookalike or brand-impersonating domain.")

    return {
        "credential_risk_score": round(min(1.0, cred_score), 4),
        "credential_evidence": cred_evidence,
        "payment_risk_score": round(min(1.0, pay_score), 4),
        "payment_evidence": pay_evidence,
    }
