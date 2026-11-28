/**
 * utils.js — Shared Pure Utilities for WebShield AI Extension v3.0
 *
 * Shared cleanly across content.js, background.js, popup.js, and Node test runners:
 * - Strict HTML escaping to prevent DOM/XSS injection in banners and popups
 * - Deterministic URL normalization & DOM feature fingerprinting for cache invalidation
 * - Cache key builders (versioned by cache schema + model version)
 * - Accurate URL lexical stats matching Python `src/features.py`
 */

(function (root) {
  "use strict";

  const CACHE_SCHEMA_VERSION = "v3";
  const TRACKING_PARAM_PREFIXES = ["utm_", "fbclid", "gclid", "mc_cid", "mc_eid", "_ga"];

  function escapeHtml(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  const PROTECTED_BRAND_DOMAINS = {
    amazon: ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.jp", "amazonaws.com"],
    flipkart: ["flipkart.com"],
    myntra: ["myntra.com"],
    meesho: ["meesho.com"],
    nykaa: ["nykaa.com"],
    tatacliq: ["tatacliq.com"],
    jiomart: ["jiomart.com"],
    snapdeal: ["snapdeal.com"],
    croma: ["croma.com"],
    vijaysales: ["vijaysales.com"],
    bigbasket: ["bigbasket.com"],
    blinkit: ["blinkit.com"],
    zepto: ["zeptonow.com", "zepto.com"],
    swiggy: ["swiggy.com"],
    zomato: ["zomato.com"],
    makemytrip: ["makemytrip.com"],
    goibibo: ["goibibo.com"],
    cleartrip: ["cleartrip.com"],
    irctc: ["irctc.co.in", "irctc.com"],
    bookmyshow: ["bookmyshow.com"],
    redbus: ["redbus.in"],
    paytm: ["paytm.com"],
    phonepe: ["phonepe.com"],
    razorpay: ["razorpay.com"],
    googlepay: ["pay.google.com", "gpay.app"],
    paypal: ["paypal.com"],
    hdfcbank: ["hdfcbank.com"],
    icicibank: ["icicibank.com"],
    axisbank: ["axisbank.com"],
    onlinesbi: ["onlinesbi.sbi", "sbi.co.in"],
    delhivery: ["delhivery.com"],
    bluedart: ["bluedart.com"],
    indiapost: ["indiapost.gov.in"],
    apple: ["apple.com", "icloud.com"],
    samsung: ["samsung.com"],
    netflix: ["netflix.com"],
    microsoft: ["microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com"],
    google: ["google.com", "google.co.in", "accounts.google.com"],
    facebook: ["facebook.com", "fb.com", "meta.com"],
    instagram: ["instagram.com"],
    whatsapp: ["whatsapp.com", "whatsapp.net"],
    telegram: ["telegram.org", "t.me"],
    binance: ["binance.com"],
    coinbase: ["coinbase.com"],
    ebay: ["ebay.com"],
    walmart: ["walmart.com"],
    shopify: ["shopify.com"],
    adidas: ["adidas.com", "adidas.co.in"],
    nike: ["nike.com"],
  };

  const HOSTED_USER_CONTENT_SUBDOMAINS = new Set([
    "sites.google.com",
    "docs.google.com",
    "drive.google.com",
    "storage.googleapis.com",
    "script.google.com",
    "colab.research.google.com",
    "firebasestorage.googleapis.com",
  ]);

  const COMPOUND_PUBLIC_SLDS = new Set([
    "co", "com", "net", "org", "gov", "edu", "ac", "mil", "nom", "nic", "gen", "firm", "ind", "res",
    "ltd", "plc", "me", "or", "ne", "go", "gr", "ed", "ad",
  ]);

  function extractRootDomain(hostname) {
    let host = String(hostname || "").toLowerCase().trim().replace(/\.$/, "");
    if (!host) return "";
    if (host.includes(":") && !host.startsWith("[")) {
      host = host.split(":", 1)[0];
    }
    const cleanIp = host.replace(/^\[|\]$/g, "");
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(cleanIp) || cleanIp.includes(":")) {
      return cleanIp;
    }
    const clean = host.startsWith("www.") ? host.slice(4) : host;
    const parts = clean.split(".").filter(Boolean);
    if (parts.length >= 3 && COMPOUND_PUBLIC_SLDS.has(parts[parts.length - 2]) && parts[parts.length - 1].length <= 3) {
      return parts.slice(-3).join(".");
    }
    return parts.length >= 2 ? parts.slice(-2).join(".") : clean;
  }

  function shannonEntropy(text) {
    const s = String(text || "");
    const n = s.length;
    if (!n) return 0;
    const counts = Object.create(null);
    for (let i = 0; i < n; i++) {
      const ch = s[i];
      counts[ch] = (counts[ch] || 0) + 1;
    }
    let ent = 0;
    for (const k in counts) {
      const p = counts[k] / n;
      ent -= p * Math.log2(p);
    }
    return Math.round(ent * 10000) / 10000;
  }

  function _deleet(s) {
    return String(s || "").replace(/[013457]/g, (c) => ({ "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t" }[c] || c));
  }

  function _editDistanceLeq1(a, b) {
    if (a === b) return true;
    const la = a.length;
    const lb = b.length;
    if (Math.abs(la - lb) > 1) return false;
    if (la === lb) {
      let diff = 0;
      for (let i = 0; i < la; i++) {
        if (a[i] !== b[i] && ++diff > 1) return false;
      }
      return diff === 1;
    }
    const shorter = la < lb ? a : b;
    const longer = la < lb ? b : a;
    let i = 0;
    let j = 0;
    let edits = 0;
    while (i < shorter.length && j < longer.length) {
      if (shorter[i] !== longer[j]) {
        if (++edits > 1) return false;
        j++;
      } else {
        i++;
        j++;
      }
    }
    return true;
  }

  function detectBrandImpersonation(hostname, titleText = "") {
    let host = String(hostname || "").toLowerCase().trim().replace(/\.$/, "");
    if (!host) return { score: 0, matchedBrand: null, brandDomainMismatch: 0 };
    if (host.includes(":") && !host.startsWith("[")) {
      host = host.split(":", 1)[0];
    }
    const root = extractRootDomain(host);
    if (!root) return { score: 0, matchedBrand: null, brandDomainMismatch: 0 };

    const userHosted = HOSTED_USER_CONTENT_SUBDOMAINS.has(host);
    const deleet = _deleet(host);
    const labels = host.split(/[.\-_]+/).filter(Boolean);
    const deleetLabels = deleet.split(/[.\-_]+/).filter(Boolean);
    const primaryLabel = root.split(".")[0] || "";
    const deleetPrimary = _deleet(primaryLabel);

    let bestScore = 0;
    let matchedBrand = null;

    const isOfficialHost = (officialRoots) =>
      !userHosted && officialRoots.some((off) => root === off || host.endsWith("." + off));

    for (const [brand, officialRoots] of Object.entries(PROTECTED_BRAND_DOMAINS)) {
      if (isOfficialHost(officialRoots)) continue;
      if (userHosted && brand === "google") continue;
      if (host.includes(brand) || deleet.includes(brand)) {
        const sc = labels.includes(brand) || deleetLabels.includes(brand) ? 0.95 : 0.85;
        if (sc > bestScore) {
          bestScore = sc;
          matchedBrand = brand;
        }
      } else if (brand.length >= 6 && (_editDistanceLeq1(primaryLabel, brand) || _editDistanceLeq1(deleetPrimary, brand))) {
        if (0.90 > bestScore) {
          bestScore = 0.90;
          matchedBrand = brand;
        }
      }
    }

    let brandDomainMismatch = bestScore >= 0.80 && matchedBrand ? 1 : 0;
    if (!brandDomainMismatch && titleText) {
      const titleClean = String(titleText).toLowerCase().replace(/[^a-z0-9 ]/g, " ");
      if (/\b(login|sign\s*in|verify|account|official|checkout|support|kyc)\b/.test(titleClean)) {
        for (const [brand, officialRoots] of Object.entries(PROTECTED_BRAND_DOMAINS)) {
          if (brand.length >= 6 && titleClean.includes(brand) && !isOfficialHost(officialRoots)) {
            brandDomainMismatch = 1;
            if (!matchedBrand) matchedBrand = brand;
            break;
          }
        }
      }
    }

    return {
      score: Math.round(bestScore * 10000) / 10000,
      matchedBrand,
      brandDomainMismatch,
    };
  }

  function isLocalNetworkHost(hostname) {
    const h = String(hostname || "").toLowerCase().trim().replace(/^\[|\]$/g, "").replace(/\.$/, "");
    if (!h) return false;
    if (h === "localhost" || h === "::1" || h === "127.0.0.1" || h === "0.0.0.0" || h.endsWith(".local")) {
      return true;
    }
    if (h.startsWith("127.") || h.startsWith("192.168.") || h.startsWith("10.")) return true;
    if (h.startsWith("172.")) {
      const second = Number(h.split(".")[1]);
      if (Number.isInteger(second) && second >= 16 && second <= 31) return true;
    }
    return false;
  }

  function normalizeUrlForCache(rawUrl) {
    try {
      const u = new URL(String(rawUrl || "").trim());
      u.hash = "";
      const kept = [];
      for (const [k, v] of u.searchParams.entries()) {
        const kl = k.toLowerCase();
        if (TRACKING_PARAM_PREFIXES.some((p) => (p.endsWith("_") ? kl.startsWith(p) : kl === p))) {
          continue;
        }
        kept.push([k, v]);
      }
      u.search = "";
      kept.forEach(([k, v]) => u.searchParams.append(k, v));
      if (!u.pathname) u.pathname = "/";
      return `${u.protocol.toLowerCase()}//${u.host.toLowerCase()}${u.pathname}${u.search}`;
    } catch {
      return String(rawUrl || "").trim();
    }
  }

  function _fnv1aHex(inputStr) {
    let hash = 0x811c9dc5;
    for (let i = 0; i < inputStr.length; i++) {
      hash ^= inputStr.charCodeAt(i);
      hash = Math.imul(hash, 0x01000193);
    }
    return (hash >>> 0).toString(16).padStart(8, "0");
  }

  function computeDomFingerprint(domFeatures) {
    if (!domFeatures || typeof domFeatures !== "object") return "nodom000";
    const f = domFeatures;
    const vector = [
      Number(f.num_password_fields || 0),
      Number(f.num_username_email_inputs || 0),
      Number(f.total_forms || 0),
      Number(f.external_forms_count || 0),
      Number(f.has_external_form_action || 0),
      Number(f.num_payment_inputs || 0),
      Number(f.has_suspicious_payment_dest || 0),
      Number(f.num_iframes || 0),
      Number(f.num_hidden_iframes || 0),
      Number(f.num_external_scripts || 0),
      Number(f.suspicious_inline_js_count || 0),
      Number(f.dynamic_dom_mutation_count || 0),
      Number(f.fake_download_button_count || 0),
      Number(f.meta_refresh_redirects || 0),
      Number(f.js_redirect_indicators || 0),
      Number(f.has_title || 0),
      Math.round(Number(f.domain_title_match_score || 0)),
      Number(f.suspicious_login_indicators || 0),
      Number(f.brand_domain_mismatch || 0),
      Number(f.mixed_content_count || 0),
      Number(f.is_https || 0),
    ].join("|");
    return `dom_${_fnv1aHex(vector)}`;
  }

  function buildCacheKey({
    url,
    domFeatures = null,
    modelVersion = "v3.0.0",
    cacheVersion = CACHE_SCHEMA_VERSION,
    backendUrl = "",
  }) {
    const normUrl = normalizeUrlForCache(url);
    const domFp = (domFeatures && domFeatures.dom_fingerprint) || computeDomFingerprint(domFeatures);
    const ver = String(modelVersion || "v3.0.0").replace(/[^a-zA-Z0-9._-]/g, "");
    const normalizedBackend = String(backendUrl || "").trim().replace(/\/+$/, "").toLowerCase();
    const backendTag = normalizedBackend ? _fnv1aHex(normalizedBackend) : "default";
    return `cache_${cacheVersion}::${backendTag}::${ver}::${normUrl}::${domFp}`;
  }

  function isCacheEntryValid(entry, currentModelVersion, nowMs, ttlMs) {
    if (!entry || typeof entry !== "object") return false;
    if (!entry.timestamp || nowMs - Number(entry.timestamp) >= ttlMs) return false;
    if (currentModelVersion && entry.model_version && entry.model_version !== currentModelVersion) {
      return false;
    }
    return true;
  }

  function computeCharStats(url) {
    const s = String(url || "");
    const n = s.length;
    if (n === 0) {
      return { spacialCharRatioInURL: 0, charContinuationRate: 0 };
    }
    const specialMatches = s.match(/[^a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]/g) || [];
    const obfMatches = s.match(/%[0-9a-fA-F]{2}/g) || [];
    const totalSpecial =
      specialMatches.length +
      obfMatches.length +
      (s.match(/=/g) || []).length +
      (s.match(/\?/g) || []).length +
      (s.match(/&/g) || []).length;

    let maxAlphaRun = 0;
    let maxDigitRun = 0;
    let curAlpha = 0;
    let curDigit = 0;
    for (let i = 0; i < n; i++) {
      const c = s[i];
      if ((c >= "a" && c <= "z") || (c >= "A" && c <= "Z")) {
        curAlpha++;
        curDigit = 0;
        if (curAlpha > maxAlphaRun) maxAlphaRun = curAlpha;
      } else if (c >= "0" && c <= "9") {
        curDigit++;
        curAlpha = 0;
        if (curDigit > maxDigitRun) maxDigitRun = curDigit;
      } else {
        curAlpha = 0;
        curDigit = 0;
      }
    }
    const contRate = (maxAlphaRun + maxDigitRun) / n;
    return {
      spacialCharRatioInURL: Math.round((totalSpecial / n) * 10000) / 10000,
      charContinuationRate: Math.round(contRate * 10000) / 10000,
    };
  }

  const api = {
    CACHE_SCHEMA_VERSION,
    PROTECTED_BRAND_DOMAINS,
    HOSTED_USER_CONTENT_SUBDOMAINS,
    escapeHtml,
    isLocalNetworkHost,
    extractRootDomain,
    shannonEntropy,
    detectBrandImpersonation,
    normalizeUrlForCache,
    computeDomFingerprint,
    buildCacheKey,
    isCacheEntryValid,
    computeCharStats,
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  } else {
    root.WebShieldUtils = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : self);

