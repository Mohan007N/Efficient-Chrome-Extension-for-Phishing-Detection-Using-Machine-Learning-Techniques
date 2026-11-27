/**
 * content.js — WebShield AI DOM & URL Metadata Inspector (Manifest V3)
 *
 * Privacy Guarantees:
 * - Inspects only structural metadata (element counts, form action hostnames, script origins).
 * - NEVER collects password values, typed form values, cookies, or authentication tokens.
 * - Explicitly discloses cross-origin iframes whose DOM cannot be inspected.
 */

(function () {
  "use strict";

  const proto = window.location.protocol;
  if (proto !== "http:" && proto !== "https:") return;

  const SERP_PATTERNS = [
    /^https?:\/\/(www\.)?google\.[a-z.]+\/search/,
    /^https?:\/\/(www\.)?bing\.com\/search/,
    /^https?:\/\/(www\.)?yahoo\.com\/search/,
    /^https?:\/\/duckduckgo\.com\/\?/,
    /^https?:\/\/(www\.)?yandex\.com\/search/,
    /^https?:\/\/(www\.)?baidu\.com\/s/,
    /^https?:\/\/search\.yahoo\.com/,
  ];

  const SCAN_KEY = "__webshield_last_scanned__";
  let debounceTimer = null;

  function countMatches(str, regex) {
    const m = str.match(regex);
    return m ? m.length : 0;
  }

  function extractRootDomain(hostname) {
    const host = (hostname || "").toLowerCase().trim().replace(/\.$/, "");
    if (!host) return "";
    const clean = host.startsWith("www.") ? host.slice(4) : host;
    const parts = clean.split(".").filter(Boolean);
    const compound = new Set(["co", "com", "net", "org", "gov", "edu", "ac"]);
    if (parts.length >= 3 && compound.has(parts[parts.length - 2]) && parts[parts.length - 1].length === 2) {
      return parts.slice(-3).join(".");
    }
    return parts.length >= 2 ? parts.slice(-2).join(".") : clean;
  }

  function isIPAddress(hostname) {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || /^\[?[0-9a-fA-F:]+\]?$/.test(hostname);
  }

  function isPageMeaningful() {
    const bodyText = (document.body?.innerText || "").trim();
    const htmlLen = (document.documentElement?.outerHTML || "").length;
    return htmlLen > 350 || bodyText.length > 40;
  }

  function extractStructuredFeatures() {
    const url = window.location.href;
    const hostname = (window.location.hostname || "").toLowerCase();
    const rootDomain = extractRootDomain(hostname);
    const parts = hostname.split(".").filter(Boolean);
    const tld = parts.length > 1 ? parts[parts.length - 1] : "com";
    const isHttps = proto === "https:" ? 1 : 0;

    const htmlSource = document.documentElement?.outerHTML || "";
    const pageText = document.body ? document.body.innerText || "" : "";
    const lowerHtml = htmlSource.toLowerCase();
    const lowerText = pageText.toLowerCase();
    const lines = htmlSource.split("\n");

    const titleEl = document.querySelector("title");
    const titleRaw = titleEl ? titleEl.textContent.trim() : "";
    const hasTitle = titleRaw ? 1 : 0;
    const titleClean = titleRaw.toLowerCase().replace(/[^a-z0-9 ]/g, " ");
    const titleWords = titleClean.split(/\s+/).filter(Boolean);
    const domainWords = hostname.replace(/[^a-z0-9 ]/g, " ").split(/\s+/).filter(w => w.length > 2);
    const domainMatches = domainWords.filter(w => titleWords.includes(w) || titleClean.includes(w)).length;
    const domainTitleMatchScore = domainWords.length > 0 ? Math.min(100, Math.round((domainMatches / domainWords.length) * 1000) / 10) : 0;

    // Group A & B: Forms, credentials, and payment input metadata (NEVER read .value!)
    const forms = Array.from(document.querySelectorAll("form"));
    const allInputs = Array.from(document.querySelectorAll("input, select, textarea"));
    const pwdInputs = document.querySelectorAll("input[type='password']").length;

    const userRe = /(user|email|login|account|phone|mobile|member|id)/i;
    const sensRe = /(card|cvv|cvc|ssn|pin|otp|routing|iban|aadhaar|pan|passport|password|passwd)/i;
    const payRe = /(card|cvv|cvc|expiry|billing|upi|razorpay|paytm|cashfree|stripe|paypal|checkout|pay_now)/i;

    let numUsernameInputs = 0;
    let numSensitiveInputs = 0;
    let numPaymentInputs = 0;
    allInputs.forEach(inp => {
      const itype = (inp.getAttribute("type") || "").toLowerCase();
      const meta = [
        inp.getAttribute("name"),
        inp.getAttribute("id"),
        inp.getAttribute("placeholder"),
        inp.getAttribute("autocomplete"),
        inp.getAttribute("aria-label"),
      ].filter(Boolean).join(" ");
      if (["email", "text", "tel"].includes(itype) && userRe.test(meta)) numUsernameInputs++;
      if (sensRe.test(meta) || itype === "password") numSensitiveInputs++;
      if (payRe.test(meta)) numPaymentInputs++;
    });

    let externalForms = 0;
    let numLoginForms = 0;
    let numHiddenCredInputs = 0;
    let hasPostForm = 0;
    let hasSuspiciousPayDest = 0;

    forms.forEach(form => {
      const method = (form.getAttribute("method") || "get").toLowerCase();
      if (method === "post") hasPostForm = 1;
      const action = (form.getAttribute("action") || "").trim();
      let isExt = false;
      if (action.startsWith("http://") || action.startsWith("https://")) {
        try {
          const ahost = new URL(action).hostname.toLowerCase();
          if (ahost && extractRootDomain(ahost) !== rootDomain && ahost !== hostname) isExt = true;
        } catch {
          isExt = true;
        }
      }
      if (isExt) externalForms++;

      const fPwds = form.querySelectorAll("input[type='password']").length;
      const fHidden = form.querySelectorAll("input[type='hidden']").length;
      const fMeta = Array.from(form.querySelectorAll("input"))
        .map(el => (el.getAttribute("name") || "") + " " + (el.getAttribute("placeholder") || ""))
        .join(" ");
      if (fPwds > 0 || (userRe.test(fMeta) && form.querySelector("button, input[type='submit']"))) {
        numLoginForms++;
        numHiddenCredInputs += fHidden;
      }
      if (isExt && payRe.test(fMeta + " " + action)) {
        hasSuspiciousPayDest = 1;
      }
    });

    const hasExternalFormAction = externalForms > 0 ? 1 : 0;
    const suspiciousLoginIndicators =
      (pwdInputs > 0 && !isHttps ? 1 : 0) +
      (pwdInputs > 0 && hasExternalFormAction ? 1 : 0);

    const hasPrepaid = /(upi|razorpay|paytm|cashfree|payu|prepaid|qr\s*code|pay\s+now|credit\s+card|debit\s+card)/i.test(lowerText + " " + lowerHtml);
    const hasCod = /(cash\s+on\s+delivery|pay\s+on\s+delivery|\bcod\s+available\b)/i.test(lowerText);
    const isCommerce = hasPrepaid || /(add\s+to\s+cart|buy\s+now|checkout|shopping\s+cart)/i.test(lowerText);
    const hasPrepaidWithoutCod = isCommerce && hasPrepaid && !hasCod ? 1 : 0;
    const hasRestrictiveRefund = /(store\s+credit|wallet\s+credit|credit\s+note\s+only|no\s+refund|non[- ]refundable|no\s+return|final\s+sale)/i.test(lowerText) ? 1 : 0;

    // Group C: Iframes, scripts, links, popups, redirects & deceptive CTAs
    const iframes = Array.from(document.querySelectorAll("iframe"));
    let numHiddenIframes = 0;
    let crossOriginIframes = 0;
    let mixedContentCount = 0;

    iframes.forEach(ifr => {
      const style = (ifr.getAttribute("style") || "").toLowerCase().replace(/\s+/g, "");
      const w = (ifr.getAttribute("width") || "").trim();
      const h = (ifr.getAttribute("height") || "").trim();
      if (style.includes("display:none") || style.includes("visibility:hidden") || ["0", "1", "1px"].includes(w) || ["0", "1", "1px"].includes(h)) {
        numHiddenIframes++;
      }
      const src = (ifr.getAttribute("src") || "").trim();
      if (isHttps && src.startsWith("http://")) mixedContentCount++;
      if (src.startsWith("http://") || src.startsWith("https://")) {
        try {
          const ih = new URL(src).hostname.toLowerCase();
          if (extractRootDomain(ih) !== rootDomain) crossOriginIframes++;
        } catch (_) {}
      }
    });

    const scripts = Array.from(document.scripts);
    let numExternalScripts = 0;
    let inlineScriptCount = 0;
    let suspiciousInlineJs = 0;
    let obfuscatedJsScore = 0;
    let dynamicMutationCount = 0;
    let popupCount = 0;
    let jsRedirectCount = 0;
    let notifPrompt = 0;

    scripts.forEach(sc => {
      const src = (sc.getAttribute("src") || "").trim();
      if (src) {
        if (isHttps && src.startsWith("http://")) mixedContentCount++;
        if (src.startsWith("http://") || src.startsWith("https://") || src.startsWith("//")) {
          try {
            const sh = new URL(src.startsWith("//") ? "https:" + src : src).hostname.toLowerCase();
            if (extractRootDomain(sh) !== rootDomain) numExternalScripts++;
          } catch (_) {}
        }
      } else {
        const code = sc.textContent || "";
        if (code.trim()) {
          inlineScriptCount++;
          suspiciousInlineJs += countMatches(code, /\b(?:eval|Function|atob|unescape|fromCharCode|document\.write)\s*\(/g);
          const hexEsc = countMatches(code, /\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}/g);
          if (hexEsc >= 8) obfuscatedJsScore = Math.min(1, Math.max(obfuscatedJsScore, 0.5 + hexEsc / 30));
          dynamicMutationCount += countMatches(code, /createElement\s*\(\s*['"](?:script|iframe)['"]|innerHTML\s*=|insertAdjacentHTML/g);
          popupCount += countMatches(code, /window\.open\(/g);
          jsRedirectCount += countMatches(code, /(?:window|document|top)\.location(?:\.href)?\s*=|location\.replace\(/g);
          if (code.includes("Notification.requestPermission")) notifPrompt = 1;
        }
      }
    });

    if (isHttps) {
      document.querySelectorAll("img[src]").forEach(img => {
        if ((img.getAttribute("src") || "").trim().toLowerCase().startsWith("http://")) mixedContentCount++;
      });
    }

    const metaRefresh = document.querySelectorAll("meta[http-equiv='refresh']").length;
    const links = Array.from(document.querySelectorAll("a[href]"));
    let emptyLinks = 0;
    let extLinks = 0;
    let selfLinks = 0;
    let fakeDownloadButtons = 0;
    const fakeDlRe = /(download\s+now|free\s+download|start\s+download|click\s+to\s+download|update\s+flash|codec\s+update|apk\s+download)/i;

    links.forEach(a => {
      const href = (a.getAttribute("href") || "").trim();
      const hlow = href.toLowerCase();
      const txt = (a.innerText || "").trim();
      let isExtLink = false;
      if (!hlow || hlow === "#" || hlow.startsWith("javascript:")) {
        emptyLinks++;
      } else if (hlow.startsWith("http://") || hlow.startsWith("https://")) {
        try {
          const lh = new URL(href).hostname.toLowerCase();
          if (extractRootDomain(lh) === rootDomain || lh === hostname) selfLinks++;
          else { extLinks++; isExtLink = true; }
        } catch { emptyLinks++; }
      } else {
        selfLinks++;
      }
      if (fakeDlRe.test(txt) && (hlow === "#" || hlow === "" || /\.(exe|msi|bat|scr|zip|apk)(\?|$)/i.test(hlow) || isExtLink)) {
        fakeDownloadButtons++;
      }
    });

    document.querySelectorAll("button, input[type='button'], input[type='submit']").forEach(btn => {
      const btxt = btn.tagName === "BUTTON" ? (btn.innerText || "") : (btn.getAttribute("value") || "");
      if (fakeDlRe.test(btxt)) fakeDownloadButtons++;
    });

    const misleadRe = /(claim\s+now|verify\s+immediately|urgent\s+action|account\s+suspended|deal\s+ends\s+in|limited\s+time\s+only|only\s+\d+\s+left|congratulations\s+you\s+won)/gi;
    const misleadingButtonCount = countMatches(pageText, misleadRe);

    const totalLinks = Math.max(1, links.length);
    const hasCopyright = /(©|copyright|all rights reserved)/i.test(pageText) || lowerHtml.includes("&copy;") ? 1 : 0;
    const emailMatches = lowerHtml.match(/[a-z0-9._%+-]+@([a-z0-9.-]+\.[a-z]{2,})/g) || [];
    const hasOfficialContact = emailMatches.some(em => {
      const dom = em.split("@")[1] || "";
      return rootDomain && (dom === rootDomain || dom.endsWith("." + rootDomain));
    }) ? 1 : 0;

    const unavailable = ["cert_details_browser_opaque"];
    if (crossOriginIframes > 0) {
      unavailable.push(`cross_origin_iframe_dom (${crossOriginIframes} frames)`);
    }

    const domFeatures = {
      num_password_fields: pwdInputs,
      num_username_email_inputs: numUsernameInputs,
      num_login_forms: numLoginForms,
      has_external_form_action: hasExternalFormAction,
      num_cross_domain_forms: externalForms,
      num_hidden_credential_inputs: numHiddenCredInputs,
      suspicious_login_indicators: suspiciousLoginIndicators,
      brand_domain_mismatch: 0,
      total_forms: forms.length,
      external_forms_count: externalForms,
      has_post_form: hasPostForm,
      num_sensitive_inputs: numSensitiveInputs,
      num_payment_inputs: numPaymentInputs,
      has_suspicious_payment_dest: hasSuspiciousPayDest,
      has_prepaid_without_cod: hasPrepaidWithoutCod,
      has_restrictive_refund_terms: hasRestrictiveRefund,
      num_iframes: iframes.length,
      num_hidden_iframes: numHiddenIframes,
      num_external_scripts: numExternalScripts,
      popup_trigger_count: popupCount,
      fake_download_button_count: fakeDownloadButtons,
      suspicious_link_ratio: Math.round((emptyLinks / totalLinks) * 10000) / 10000,
      meta_refresh_redirects: metaRefresh,
      js_redirect_indicators: jsRedirectCount,
      misleading_button_count: misleadingButtonCount,
      external_link_ratio: Math.round((extLinks / totalLinks) * 10000) / 10000,
      notification_prompt_requested: notifPrompt,
      inline_script_count: inlineScriptCount,
      suspicious_inline_js_count: suspiciousInlineJs,
      obfuscated_js_score: Math.round(obfuscatedJsScore * 10000) / 10000,
      dynamic_dom_mutation_count: dynamicMutationCount,
      html_line_count: lines.length,
      has_title: hasTitle,
      domain_title_match_score: domainTitleMatchScore,
      has_copyright_notice: hasCopyright,
      has_official_contact_cue: hasOfficialContact,
      is_https: isHttps,
      mixed_content_count: mixedContentCount,
      cross_origin_iframes_uninspected: crossOriginIframes,
      unavailable_signals: unavailable,
    };

    const obfChars = countMatches(url, /%[0-9a-fA-F]{2}/g);
    const letters = countMatches(url, /[a-zA-Z]/g);
    const digits = countMatches(url, /[0-9]/g);
    const socialNets = ["facebook.com", "twitter.com", "x.com", "instagram.com", "linkedin.com", "youtube.com", "github.com"];
    const hasSocialNet = links.some(a => socialNets.some(s => (a.href || "").includes(s))) ? 1 : 0;

    return {
      url,
      hostname,
      URLLength: url.length,
      DomainLength: hostname.length,
      IsDomainIP: isIPAddress(hostname) ? 1 : 0,
      TLD: tld,
      TLDLength: tld.length,
      NoOfSubDomain: Math.max(0, parts.length - 2),
      HasObfuscation: obfChars > 0 ? 1 : 0,
      NoOfObfuscatedChar: obfChars,
      ObfuscationRatio: url.length ? obfChars / url.length : 0,
      NoOfLettersInURL: letters,
      LetterRatioInURL: url.length ? letters / url.length : 0,
      NoOfDegitsInURL: digits,
      DegitRatioInURL: url.length ? digits / url.length : 0,
      NoOfEqualsInURL: (url.match(/=/g) || []).length,
      NoOfQMarkInURL: (url.match(/\?/g) || []).length,
      NoOfAmpersandInURL: (url.match(/&/g) || []).length,
      NoOfOtherSpecialCharsInURL: countMatches(url, /[^a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]/g),
      SpacialCharRatioInURL: 0,
      CharContinuationRate: 0,
      IsHTTPS: isHttps,
      LineOfCode: lines.length,
      LargestLineLength: lines.reduce((m, l) => Math.max(m, l.length), 0),
      HasTitle: hasTitle,
      DomainTitleMatchScore: domainTitleMatchScore,
      URLTitleMatchScore: domainTitleMatchScore,
      HasFavicon: document.querySelector("link[rel*='icon']") ? 1 : 0,
      Robots: 0,
      IsResponsive: document.querySelector("meta[name='viewport']") ? 1 : 0,
      NoOfURLRedirect: metaRefresh,
      NoOfSelfRedirect: 0,
      HasDescription: document.querySelector("meta[name='description']") ? 1 : 0,
      NoOfPopup: popupCount,
      NoOfiFrame: iframes.length,
      HasExternalFormSubmit: hasExternalFormAction,
      HasSocialNet: hasSocialNet,
      HasSubmitButton: document.querySelector("input[type='submit'], button") ? 1 : 0,
      HasHiddenFields: document.querySelectorAll("input[type='hidden']").length > 0 ? 1 : 0,
      HasPasswordField: pwdInputs > 0 ? 1 : 0,
      Bank: /(bank|banking|account|login|signin|verify|secure)/i.test(lowerText) ? 1 : 0,
      Pay: isCommerce ? 1 : 0,
      Crypto: /(bitcoin|ethereum|crypto|wallet|blockchain|btc|eth)/i.test(lowerText) ? 1 : 0,
      HasCopyrightInfo: hasCopyright,
      NoOfImage: document.querySelectorAll("img").length,
      NoOfCSS: document.querySelectorAll("link[rel='stylesheet']").length,
      NoOfJS: document.querySelectorAll("script[src]").length,
      NoOfSelfRef: selfLinks,
      NoOfEmptyRef: emptyLinks,
      NoOfExternalRef: extLinks,
      dom_features: domFeatures,
    };
  }

  const BANNER_ID = "__webshield_banner__";
  let autoDismissTimer = null;

  function injectWarningBanner(data) {
    const existing = document.getElementById(BANNER_ID);
    if (existing) existing.remove();
    if (autoDismissTimer) clearTimeout(autoDismissTimer);

    const assessment = data.assessment || {};
    const riskLevel = (assessment.overall_risk_level || data.risk_level || "LOW").toUpperCase();
    if (riskLevel === "LOW" || data.user_trusted) return;

    const evidence = (assessment.evidence || data.top_indicators || []).slice(0, 4);
    const action = assessment.recommended_action || "Proceed carefully before entering personal or payment details.";
    const accent = riskLevel === "CRITICAL" ? "#e11d48" : (riskLevel === "HIGH" ? "#f97316" : "#f59e0b");

    const banner = document.createElement("div");
    banner.id = BANNER_ID;
    banner.style.cssText = `
      position: fixed !important; top: 0 !important; left: 0 !important; right: 0 !important;
      z-index: 2147483647 !important; background: #0d111a !important; color: #f8fafc !important;
      border-bottom: 2px solid ${accent} !important; padding: 10px 18px !important;
      font-family: -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', sans-serif !important;
      box-shadow: 0 10px 30px rgba(0,0,0,0.6) !important; box-sizing: border-box !important;
    `;

    const evHtml = evidence.map(e => `<div style="font-size:11px;color:#cbd5e1;margin-top:2px;">• ${e}</div>`).join("");
    banner.innerHTML = `
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:14px;">
        <div style="min-width:0;">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
            <span style="font-size:13px;font-weight:700;color:#ffffff;">WebShield Safety Notice</span>
            <span style="font-size:10px;font-weight:700;padding:2px 8px;border-radius:999px;background:${accent}26;color:${accent};border:1px solid ${accent}66;">${riskLevel} RISK</span>
          </div>
          <div style="font-size:11.5px;color:#e2e8f0;margin-top:3px;">${action}</div>
          ${evHtml}
        </div>
        <div style="display:flex;gap:8px;flex-shrink:0;align-items:center;">
          <button id="__ws_leave__" style="background:${accent};border:none;color:#fff;padding:6px 12px;border-radius:6px;font-size:11.5px;font-weight:600;cursor:pointer;">Go Back</button>
          <button id="__ws_close__" style="background:transparent;border:1px solid rgba(255,255,255,0.2);color:#94a3b8;padding:5px 9px;border-radius:6px;cursor:pointer;">✕</button>
        </div>
      </div>
    `;
    document.documentElement.appendChild(banner);
    banner.querySelector("#__ws_close__")?.addEventListener("click", () => banner.remove());
    banner.querySelector("#__ws_leave__")?.addEventListener("click", () => {
      if (window.history.length > 1) window.history.back();
      else window.location.href = "https://www.google.com";
    });
    if (riskLevel === "MEDIUM") {
      autoDismissTimer = setTimeout(() => banner.remove(), 8000);
    }
  }

  function runScan(force = false) {
    const currentUrl = window.location.href;
    if (SERP_PATTERNS.some(p => p.test(currentUrl))) return;
    if (!force && window[SCAN_KEY] === currentUrl) return;
    if (!isPageMeaningful()) {
      setTimeout(() => { if (isPageMeaningful()) dispatchScan(currentUrl, force); }, 1200);
      return;
    }
    dispatchScan(currentUrl, force);
  }

  function dispatchScan(currentUrl, force) {
    window[SCAN_KEY] = currentUrl;
    try {
      const payload = extractStructuredFeatures();
      chrome.runtime.sendMessage({ type: "ANALYZE_PAGE", url: currentUrl, force, features: payload }, () => {
        if (chrome.runtime.lastError) return;
      });
    } catch (err) {
      console.warn("[WebShield] Feature extraction error:", err);
    }
  }

  function scheduleDebouncedScan(force = false) {
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => runScan(force), 700);
  }

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "PHISHING_RESULT" && message.data) {
      injectWarningBanner(message.data);
    }
    if (message.type === "TRIGGER_RESCAN") {
      delete window[SCAN_KEY];
      runScan(true);
      sendResponse({ ok: true });
      return true;
    }
  });

  // Initial scan + debounced SPA URL change listeners
  scheduleDebouncedScan(false);
  window.addEventListener("popstate", () => scheduleDebouncedScan(false));
  window.addEventListener("hashchange", () => scheduleDebouncedScan(false));
})();
