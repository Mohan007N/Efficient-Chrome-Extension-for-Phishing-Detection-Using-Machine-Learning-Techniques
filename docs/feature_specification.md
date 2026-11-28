# WebShield AI v3.0 — Feature Specification (Python & Chrome Extension)

Every ML model validates exact column names and ordering via `validate_url_feature_schema()` (`src/features.py`) and `validate_dom_feature_schema()` (`src/dom_features.py`). Missing or reordered columns raise `ValueError` at training and `PhishingPredictor` raises/marks `schema_mismatch` rather than silently zero-filling corrupted inputs.

---

## 1. Model 1 — URL Risk Classifier (`URL_FEATURE_COLUMNS`, 33 Features)

Computed canonically in [`src/features.py`](../src/features.py) (`extract_url_features()`). Leading `www.` prefixes are canonicalized before lexical extraction so classifiers do not overfit dataset crawl prefixes.

| # | Feature Name | Type | Default / Missing | Expected Range | Security Meaning & Extraction Method |
| ---: | --- | --- | --- | --- | --- |
| 1 | `url_length` | `int` | `0` | `0–4096+` | Normalized URL character length (`len(norm_url)`). |
| 2 | `domain_length` | `int` | `0` | `0–255` | Canonical hostname length (`len(canon_host)`). |
| 3 | `path_length` | `int` | `0` | `0–4096` | URL path character length. |
| 4 | `query_length` | `int` | `0` | `0–4096` | URL query string length. |
| 5 | `num_subdomains` | `int` | `0` | `0–20` | PSL-aligned subdomain label count (`tldextract`). |
| 6 | `num_dots` | `int` | `0` | `0–100` | Dot `.` occurrences in normalized URL. |
| 7 | `num_hyphens_domain` | `int` | `0` | `0–50` | Hyphen `-` count in canonical hostname. |
| 8 | `num_digits_url` | `int` | `0` | `0–1000` | Total numeric digits across URL. |
| 9 | `num_digits_domain` | `int` | `0` | `0–100` | Total numeric digits in hostname. |
| 10 | `num_special_chars` | `int` | `0` | `0–1000` | Count of `-_?=&%/@+!~$;,` in URL. |
| 11 | `special_char_ratio` | `float` | `0.0` | `0.0–1.0` | Non-alphanumeric character ratio (`spacialCharRatioInURL`). |
| 12 | `is_ip_address` | `int` | `0` | `{0, 1}` | `1` if hostname parses as IPv4/IPv6 literal (`ipaddress.ip_address`). |
| 13 | `is_punycode_or_idn` | `int` | `0` | `{0, 1}` | `1` if hostname contains `xn--` Punycode label or non-ASCII chars. |
| 14 | `has_unicode_homoglyph` | `int` | `0` | `{0, 1}` | `1` if hostname contains mixed-script/confusable characters. |
| 15 | `has_unusual_port` | `int` | `0` | `{0, 1}` | `1` if explicit URL port is not `80` or `443`. |
| 16 | `has_userinfo_in_url` | `int` | `0` | `{0, 1}` | `1` if URL authority contains `@` userinfo credential trap. |
| 17 | `has_redirect_indicator` | `int` | `0` | `{0, 1}` | `1` if query keys/values match open-redirect patterns (`redirect=`, `next=`, `url=`, `http`). |
| 18 | `is_url_shortener` | `int` | `0` | `{0, 1}` | `1` if registered root domain is in `SHORTENER_DOMAINS`. |
| 19 | `has_url_obfuscation` | `int` | `0` | `{0, 1}` | `1` if excess percent-encoding (`%xx`), hex-encoded host, or `//` tricks appear. |
| 20 | `path_depth` | `int` | `0` | `0–30` | Count of non-empty path segments. |
| 21 | `num_query_params` | `int` | `0` | `0–50` | Count of parsed query parameters (`parse_qs`). |
| 22 | `url_entropy` | `float` | `0.0` | `0.0–8.0` | Shannon character entropy of full URL. |
| 23 | `domain_entropy` | `float` | `0.0` | `0.0–6.0` | Shannon character entropy of canonical hostname. |
| 24 | `tld_length` | `int` | `3` | `1–24` | Suffix length from PSL suffix (`len(tld)`). |
| 25 | `is_suspicious_tld` | `int` | `0` | `{0, 1}` | `1` if PSL suffix is in elevated-abuse TLDs (`top`, `xyz`, `tk`, `icu`, etc.). |
| 26 | `suspicious_keyword_count` | `int` | `0` | `0–20` | Phishing/lure tokens across host and path (`verify`, `kyc`, `signin`, `wallet`, etc.). |
| 27 | `is_https` | `int` | `0` | `{0, 1}` | `1` if scheme is `https`, `0` otherwise (`http`). |
| 28 | `brand_similarity_score` | `float` | `0.0` | `0.0–1.0` | Homograph/leet/edit-distance brand impersonation similarity vs `PROTECTED_BRANDS` when domain is not an official brand domain. |
| 29 | `typosquat_edit_distance` | `int` | `99` | `0–99` | Minimum Levenshtein distance from domain labels to `PROTECTED_BRANDS` (`0` for exact impersonation label on untrusted domain, `99` when benign/far). |
| 30 | `char_continuation_rate` | `float` | `0.0` | `0.0–1.0` | Longest consecutive alpha+digit+symbol run normalized by domain length. |
| 31 | `letter_ratio` | `float` | `0.0` | `0.0–1.0` | Alphabetic character ratio in URL. |
| 32 | `digit_ratio` | `float` | `0.0` | `0.0–1.0` | Digit character ratio in URL. |
| 33 | `tld` | `str` -> `int` | `"com"` (`-1` unseen) | Encoded ordinal | PSL public suffix encoded by training `OrdinalEncoder(unknown_value=-1)`. |

---

## 2. Model 2 — DOM Behaviour Classifier (`DOM_FEATURE_COLUMNS`, 36 Features)

Extracted identically by Python single-pass `lxml` ([`src/dom_features.py`](../src/dom_features.py)) and Chrome Extension DOM observer ([`chrome_extension/content.js`](../chrome_extension/content.js)) without collecting passwords, typed input values, or cookies.

| Group | # | Feature Name | Type | Default | Range | Description |
| --- | ---: | --- | --- | ---: | --- | --- |
| **A: Credential & Login** | 1 | `num_password_fields` | `int` | `0` | `0–50+` | Count of `input[type=password]` nodes. |
| | 2 | `num_username_email_inputs` | `int` | `0` | `0–50+` | Username/email/phone input nodes matching `user\|email\|login\|phone`. |
| | 3 | `num_login_forms` | `int` | `0` | `0–20+` | Forms containing password or username+submit triggers. |
| | 4 | `has_external_form_action` | `int` | `0` | `{0, 1}` | `1` if any form submits to a different registrable PSL root domain. |
| | 5 | `num_cross_domain_forms` | `int` | `0` | `0–20` | Total forms whose `action` points cross-domain. |
| | 6 | `num_hidden_credential_inputs` | `int` | `0` | `0–100` | `input[type=hidden]` inside login forms. |
| | 7 | `suspicious_login_indicators` | `int` | `0` | `0–3` | Sum of `(pwd>0 & !https)`, `(pwd>0 & external_form)`, `(login_forms>0 & brand_mismatch)`. |
| | 8 | `brand_domain_mismatch` | `int` | `0` | `{0, 1}` | `1` if `<title>` claims a protected brand while host is NOT an official brand domain. |
| **B: Forms & Payments** | 9 | `total_forms` | `int` | `0` | `0–100` | Total `<form>` elements on page. |
| | 10 | `external_forms_count` | `int` | `0` | `0–20` | Count of cross-domain forms (`action` host differs from page PSL root). |
| | 11 | `has_post_form` | `int` | `0` | `{0, 1}` | `1` if any form uses HTTP `POST`. |
| | 12 | `num_sensitive_inputs` | `int` | `0` | `0–50` | Inputs matching card/CVV/OTP/SSN/PIN/Aadhaar/PAN/password attributes. |
| | 13 | `num_payment_inputs` | `int` | `0` | `0–50` | Payment-related input metadata count (`card`, `cvv`, `upi`, `billing`). |
| | 14 | `has_suspicious_payment_dest` | `int` | `0` | `{0, 1}` | `1` if cross-domain form submits payment metadata externally. |
| | 15 | `has_prepaid_without_cod` | `int` | `0` | `{0, 1}` | `1` when commercial checkout mentions UPI/prepaid without COD cues. |
| | 16 | `has_restrictive_refund_terms` | `int` | `0` | `{0, 1}` | `1` when page contains store-credit-only / no-refund / final-sale clauses. |
| **C: Ads, Redirects & Deception** | 17 | `num_iframes` | `int` | `0` | `0–50+` | Total `<iframe>` elements. |
| | 18 | `num_hidden_iframes` | `int` | `0` | `0–50+` | Hidden/zero/1px `<iframe>` elements (`display:none`, `visibility:hidden`, width/height `<=1`). |
| | 19 | `num_external_scripts` | `int` | `0` | `0–250` | External `<script src=...>` elements on third-party root domains. |
| | 20 | `popup_trigger_count` | `int` | `0` | `0–50` | `window.open(` call occurrences inside inline scripts. |
| | 21 | `fake_download_button_count` | `int` | `0` | `0–50` | Suspicious download CTAs targeting `#`, external domains, or `.exe/.apk/.zip`. |
| | 22 | `suspicious_link_ratio` | `float` | `0.0` | `0.0–1.0` | Fraction of `<a>` links with empty, `#`, or `javascript:` targets. |
| | 23 | `meta_refresh_redirects` | `int` | `0` | `0–10` | `<meta http-equiv="refresh">` redirect count. |
| | 24 | `js_redirect_indicators` | `int` | `0` | `0–20` | `location.href =` / `location.replace(` script patterns. |
| | 25 | `misleading_button_count` | `int` | `0` | `0–50` | Urgency/bait CTAs (`claim now`, `verify immediately`, `account suspended`, etc.). |
| | 26 | `external_link_ratio` | `float` | `0.0` | `0.0–1.0` | Fraction of anchor tags targeting third-party domains. |
| | 27 | `notification_prompt_requested` | `int` | `0` | `{0, 1}` | `1` if `Notification.requestPermission` appears in inline JS. |
| **D: JS & Architecture** | 28 | `inline_script_count` | `int` | `0` | `0–200` | Inline `<script>` tags with non-empty source. |
| | 29 | `suspicious_inline_js_count` | `int` | `0` | `0–50` | Occurrences of `eval(`, `Function(`, `atob(`, `unescape(`, `fromCharCode(`, `document.write(`. |
| | 30 | `obfuscated_js_score` | `float` | `0.0` | `0.0–1.0+` | Entropy (>5.2) / `\xHH` & `\uHHHH` hex-escape obfuscation score. |
| | 31 | `dynamic_dom_mutation_count` | `int` | `0` | `0–50` | `createElement('script'|'iframe')`, `innerHTML=`, `insertAdjacentHTML` patterns. |
| | 32 | `html_line_count` | `int` | `0` | `0–50000` | Total lines in serialized DOM HTML. |
| | 33 | `has_title` | `int` | `0` | `{0, 1}` | `1` if `<title>` has non-empty text. |
| | 34 | `domain_title_match_score` | `float` | `0.0` | `0.0–100.0` | Percentage of meaningful hostname words appearing in page `<title>`. |
| | 35 | `has_copyright_notice` | `int` | `0` | `{0, 1}` | `1` if copyright symbol/notice appears in text or footer HTML. |
| | 36 | `has_official_contact_cue` | `int` | `0` | `{0, 1}` | `1` if a contact email on page shares the page's registered PSL `root_domain`. |

---

## 3. DOM Observability Metadata (`DOM_OBSERVABILITY_COLUMNS`, Excluded From ML Matrix)

Never passed into Model 2 (`DOM_FEATURE_COLUMNS`), used strictly by `HybridRiskEngine` for security diagnostics and honest missing-evidence disclosure:

| Feature Name | Type | Default | Range | Usage |
| --- | --- | --- | --- | --- |
| `is_https` | `int` | `0` (`None` if omitted -> `UNKNOWN`) | `{0, 1}` | Determines `SECURE_HTTPS` vs `INSECURE_HTTP` separately from phishing likelihood. |
| `mixed_content_count` | `int` | `0` | `0–100` | Flags `http://` subresources (`iframe`/`script`/`img`) loaded inside HTTPS pages (`HTTPS_MIXED_CONTENT`). |
| `cross_origin_iframes_uninspected` | `int` | `0` | `0–50` | Discloses opaque cross-origin frames browser extensions cannot inspect internally. |

---

## 4. Chrome Extension Payload Notes (`chrome_extension/content.js`)

- Emits all `36` `DOM_FEATURE_COLUMNS` keys plus `is_https`, `mixed_content_count`, `cross_origin_iframes_uninspected`, `unavailable_signals`, `analysis_mode="extension_dom"`, and deterministic `dom_fingerprint`.
- Rejects credential harvesting: NEVER reads `input.value`, `document.cookie`, or session headers.
- Empty `{}` DOM payloads are normalized with `has_dom_observation = False` in `backend/predictor.py` (`is_meaningful_dom_observation`) so empty telemetry cannot impersonate a safe page observation.

