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
      Number(f.mixed_content_count || 0),
      Number(f.is_https || 0),
    ].join("|");
    return `dom_${_fnv1aHex(vector)}`;
  }

  function buildCacheKey({ url, domFeatures = null, modelVersion = "v3.0.0", cacheVersion = CACHE_SCHEMA_VERSION }) {
    const normUrl = normalizeUrlForCache(url);
    const domFp = (domFeatures && domFeatures.dom_fingerprint) || computeDomFingerprint(domFeatures);
    const ver = String(modelVersion || "v3.0.0").replace(/[^a-zA-Z0-9._-]/g, "");
    return `cache_${cacheVersion}::${ver}::${normUrl}::${domFp}`;
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
    escapeHtml,
    isLocalNetworkHost,
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

