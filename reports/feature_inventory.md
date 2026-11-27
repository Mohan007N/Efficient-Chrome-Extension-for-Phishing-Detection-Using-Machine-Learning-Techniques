# Feature Inventory

This document catalogs every feature currently used by the project, features dropped for leakage/skew, and the separated **URL Feature Schema** and **DOM Behaviour Feature Schema** designed for the upgraded multi-model architecture.

---

## 1. Legacy & Current Features (Saved Model: 56 Features)

### 1.1 Dropped Columns from Raw PhiUSIIL (`src/preprocessing.py`)
| Column | Reason Dropped |
|---|---|
| `URL`, `Domain`, `Title` | Unique free-text identifiers / metadata (used only to derive lexical/brand features and for domain-grouped splitting) |
| `URLSimilarityIndex` | Label leakage (pre-computed against ground-truth target/legitimate corpus; `100.0` for legitimate) |
| `TLDLegitimateProb` | Target leakage (derived from labeled corpus frequencies) |
| `URLCharProb` | Target leakage (derived from labeled corpus character distributions) |
| `Robots` | Train/inference skew (hardcoded to `0` in `chrome_extension/content.js`) |
| `NoOfSelfRedirect` | Train/inference skew (not observable from DOM content script; hardcoded to `0`) |

### 1.2 Base 46 PhiUSIIL Features Currently in `models/feature_columns.pkl`
1. **URL Structure (19)**: `URLLength`, `DomainLength`, `IsDomainIP`, `TLD` (LabelEncoded), `CharContinuationRate`, `TLDLength`, `NoOfSubDomain`, `HasObfuscation`, `NoOfObfuscatedChar`, `ObfuscationRatio`, `NoOfLettersInURL`, `LetterRatioInURL`, `NoOfDegitsInURL`, `DegitRatioInURL`, `NoOfEqualsInURL`, `NoOfQMarkInURL`, `NoOfAmpersandInURL`, `NoOfOtherSpecialCharsInURL`, `SpacialCharRatioInURL`
2. **Protocol & Document Metadata (8)**: `IsHTTPS`, `LineOfCode`, `LargestLineLength`, `HasTitle`, `DomainTitleMatchScore`, `URLTitleMatchScore`, `HasFavicon`, `IsResponsive`
3. **DOM / Form / Keyword / Resource Counts (19)**: `NoOfURLRedirect`, `HasDescription`, `NoOfPopup`, `NoOfiFrame`, `HasExternalFormSubmit`, `HasSocialNet`, `HasSubmitButton`, `HasHiddenFields`, `HasPasswordField`, `Bank`, `Pay`, `Crypto`, `HasCopyrightInfo`, `NoOfImage`, `NoOfCSS`, `NoOfJS`, `NoOfSelfRef`, `NoOfEmptyRef`, `NoOfExternalRef`

### 1.3 Existing 10 Shared Engineered Features (`src/features.py`)
`DomainHyphenCount`, `DomainDigitCount`, `IsSuspiciousStoreTLD`, `HasScamDomainKeyword`, `BrandImpersonationScore`, `PayWithoutTrustRatio`, `EmptyToSelfLinkRatio`, `ExternalToSelfLinkRatio`, `AssetsPerLineRatio`, `CommerceAuthRiskInteraction`

> **Audit Note:** Features #6–#10 in `src/features.py` currently mix URL and DOM signals inside one monolithic feature vector, and lack URL entropy, Punycode/IDN detection, unusual ports, URL shortener detection, dot count, and deep DOM behaviour granularity.

---

## 2. Target Separated Architecture: URL Features (`src/features.py`)

Used exclusively by **Model 1 (URL Risk Classifier)** and **Model 3 (Brand Impersonation Detector)** so URL evaluation never breaks when HTML/DOM is unavailable.

| Feature | Type | Description |
|---|---|---|
| `url_length` | int | Total character length of normalized URL |
| `domain_length` | int | Character length of hostname |
| `path_length` | int | Character length of URL path |
| `query_length` | int | Character length of query string |
| `num_subdomains` | int | Subdomain depth beyond root domain |
| `num_dots` | int | Count of `.` characters in URL |
| `num_hyphens_domain` | int | Count of `-` characters in hostname |
| `num_digits_url` | int | Count of numeric digits in URL |
| `num_digits_domain` | int | Count of numeric digits in hostname |
| `num_special_chars` | int | Count of special characters (`@`, `?`, `=`, `&`, `%`, `_`, etc.) |
| `is_ip_address` | int (0/1) | Hostname is an IPv4 or IPv6 literal |
| `is_punycode_or_idn` | int (0/1) | Hostname uses `xn--` Punycode or non-ASCII characters |
| `has_unusual_port` | int (0/1) | Non-standard explicit port (not 80/443) |
| `is_url_shortener` | int (0/1) | Domain matches known URL shortener service |
| `has_url_obfuscation` | int (0/1) | Percent-encoding or `@` userinfo trick in URL |
| `url_entropy` | float | Shannon character entropy of the URL string |
| `domain_entropy` | float | Shannon character entropy of hostname |
| `tld_length` | int | Character length of Top-Level Domain |
| `is_suspicious_tld` | int (0/1) | TLD belongs to elevated-abuse TLD set |
| `suspicious_keyword_count` | int | Count of credential/lure/payment tokens in URL |
| `is_https` | int (0/1) | Scheme is HTTPS (reported separately as connection security; never treated alone as phishing proof) |
| `brand_similarity_score` | float | Max normalized similarity / impersonation score vs protected brands when not official domain |
| `typosquat_edit_distance` | int | Minimum Damerau/Levenshtein edit distance to closest protected brand (`99` if unrelated or official) |
| `char_continuation_rate` | float | Repeated consecutive character ratio |
| `letter_ratio` | float | Ratio of ASCII letters to URL length |
| `digit_ratio` | float | Ratio of digits to URL length |
| `tld_encoded` | int | Target-safe integer encoding of TLD |

---

## 3. Target Separated Architecture: DOM & HTML Behaviour Features (`src/dom_features.py`)

Extracted identically from static HTML (via BeautifulSoup/HTMLParser on `PhreshPhish` & custom verified HTML fixtures) and from live Chrome extension DOM inspection (`chrome_extension/content.js`). Never collects raw passwords, form values, cookies, or tokens.

### 3.1 Group A: Login & Credential Features
| Feature | Type | Description |
|---|---|---|
| `num_password_fields` | int | Count of `input[type=password]` elements |
| `num_username_email_inputs` | int | Count of email/username/login text inputs |
| `num_login_forms` | int | Forms containing password or username+submit patterns |
| `has_external_form_action` | int (0/1) | Any form submitting to a different root domain |
| `num_cross_domain_forms` | int | Count of forms with external domain action targets |
| `num_hidden_credential_inputs` | int | Hidden inputs inside login/credential forms |
| `suspicious_login_indicators` | int | Login form over HTTP or external submission or missing domain-title match |
| `brand_domain_mismatch` | int (0/1) | Page text/title claims a protected brand that differs from host root domain |

### 3.2 Group B: Form & Payment Features
| Feature | Type | Description |
|---|---|---|
| `total_forms` | int | Total `<form>` tags on page |
| `external_forms_count` | int | Forms pointing to external root domains |
| `has_post_form` | int (0/1) | Presence of `method="post"` form |
| `num_sensitive_inputs` | int | Inputs matching card/CVV/OTP/SSN/PIN/account labels (metadata names only, never values) |
| `num_payment_inputs` | int | Payment/checkout/UPI/card inputs |
| `has_suspicious_payment_dest` | int (0/1) | Payment form submitting to unverified external host |
| `has_prepaid_without_cod` | int (0/1) | Storefront checkout/UPI/payment cues with restrictive/missing buyer protections |
| `has_restrictive_refund_terms` | int (0/1) | Detects `no refund`, `non-refundable`, `store credit only`, `wallet credit` |

### 3.3 Group C: Advertisement, Redirect & Deceptive Behaviour
| Feature | Type | Description |
|---|---|---|
| `num_iframes` | int | Count of `<iframe>` tags (note: cross-origin iframe internals are inaccessible and flagged as uninspected) |
| `num_hidden_iframes` | int | Hidden or zero/1px dimension iframes |
| `num_external_scripts` | int | `<script src="...">` pointing outside root domain |
| `popup_trigger_count` | int | Observable `window.open` / popup/modal triggers |
| `fake_download_button_count` | int | Misleading download/play/claim CTAs or mismatched download hrefs |
| `suspicious_link_ratio` | float | Ratio of `#` / `javascript:` / empty / obfuscated links to total links |
| `meta_refresh_redirects` | int | Count of `<meta http-equiv="refresh">` redirects |
| `js_redirect_indicators` | int | Observable `location.href` / `location.replace` redirect patterns in inline scripts |
| `misleading_button_count` | int | Urgency/scarcity/deceptive CTA text (`claim now`, `verify immediately`, `deal ends in`) |
| `external_link_ratio` | float | Ratio of third-party external `<a>` links to total `<a>` links |
| `notification_prompt_requested` | int (0/1) | Observable `Notification.requestPermission` call or browser permission prompt cue |

### 3.4 Group D: JavaScript & Webpage Architecture
| Feature | Type | Description |
|---|---|---|
| `inline_script_count` | int | Count of inline `<script>` blocks |
| `suspicious_inline_js_count` | int | Count of `eval(`, `Function(`, `atob(`, `fromCharCode`, `document.write(` patterns |
| `obfuscated_js_score` | float | Normalized indicator for hex/unicode escapes or high-entropy script blobs |
| `dynamic_dom_mutation_count` | int | Observable `createElement('script'/'iframe')` / `appendChild` / `innerHTML` script sinks |
| `html_line_count` | int | HTML source line count |
| `has_title` | int (0/1) | Page contains non-empty `<title>` |
| `domain_title_match_score` | float | Lexical overlap between hostname tokens and `<title>` |
| `has_copyright_notice` | int (0/1) | Presence of copyright metadata |
| `has_official_contact_cue` | int (0/1) | Domain-matching email or physical/corporate contact metadata |

### 3.5 Group E: Security & Observability Metadata (Not fed as fake signals)
| Field | Type | Description |
|---|---|---|
| `is_https` | int (0/1) | Transport protocol is HTTPS |
| `mixed_content_count` | int | Count of `http://` subresources (`img`/`script`/`iframe`) on HTTPS pages |
| `cross_origin_iframes_uninspected` | int | Count of cross-origin `<iframe>` elements whose internal DOM could not be inspected |
| `unavailable_signals` | list[str] | Explicit list of fields unavailable in the current inspection context (e.g., `redirect_chain`, `cert_details` in content script) |

