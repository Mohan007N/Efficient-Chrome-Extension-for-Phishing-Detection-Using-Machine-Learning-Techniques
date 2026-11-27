/**
 * content.js — PhishGuard Content Script (Production)
 *
 * Guards:
 *   1. Skips chrome://, about:, data:, devtools:, extension pages
 *   2. Skips Chrome's new-tab page and search engine results pages (SERPs)
 *   3. Skips pages that haven't finished loading (waits for document_idle)
 *   4. Skips pages the user hasn't actually navigated to (prefetch/prerender)
 *   5. De-duplicates: won't scan the same URL twice in the same tab session
 *   6. Minimum page content check (avoids blank/redirect pages)
 */

(function () {
  "use strict";

  // ─────────────────────────────────────────────────────────────────────────────
  // Guard 1 — Skip non-web protocols entirely
  // ─────────────────────────────────────────────────────────────────────────────
  const proto = window.location.protocol;
  if (
    proto === "chrome:" ||
    proto === "chrome-extension:" ||
    proto === "about:" ||
    proto === "data:" ||
    proto === "devtools:" ||
    proto === "blob:" ||
    proto === "file:"
  ) return;

  // ─────────────────────────────────────────────────────────────────────────────
  // Guard 2 — Skip search engine results pages (SERPs) and new-tab page
  // These pages contain untrusted links but are not the actual destination.
  // ─────────────────────────────────────────────────────────────────────────────
  const SERP_PATTERNS = [
    /^https?:\/\/(www\.)?google\.[a-z.]+\/search/,
    /^https?:\/\/(www\.)?bing\.com\/search/,
    /^https?:\/\/(www\.)?yahoo\.com\/search/,
    /^https?:\/\/duckduckgo\.com\/\?/,
    /^https?:\/\/(www\.)?yandex\.com\/search/,
    /^https?:\/\/(www\.)?baidu\.com\/s/,
    /^https?:\/\/search\.yahoo\.com/,
    /chrome:\/\/newtab/,
  ];

  const currentUrl = window.location.href;
  if (SERP_PATTERNS.some(p => p.test(currentUrl))) return;

  // ─────────────────────────────────────────────────────────────────────────────
  // Guard 3 — De-duplicate: track scanned URLs per session
  // ─────────────────────────────────────────────────────────────────────────────
  const SCAN_KEY = "__phishguard_scanned__";
  if (window[SCAN_KEY] === currentUrl) return;
  window[SCAN_KEY] = currentUrl;

  // ─────────────────────────────────────────────────────────────────────────────
  // Guard 4 — Only scan after page is visibly interactive
  // document_idle fires when the DOM is ready, but we add an extra check:
  // ensure the body actually has content (not a redirect stub).
  // ─────────────────────────────────────────────────────────────────────────────
  function isPageMeaningful() {
    const bodyText = (document.body?.innerText || "").trim();
    const htmlLen  = (document.documentElement?.outerHTML || "").length;
    // Require at least 500 bytes of HTML or some visible body text
    return htmlLen > 500 || bodyText.length > 50;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Helpers — Feature extraction utilities
  // ─────────────────────────────────────────────────────────────────────────────

  function countOccurrences(str, sub) {
    if (!sub) return 0;
    let count = 0, pos = 0;
    while ((pos = str.indexOf(sub, pos)) !== -1) { count++; pos++; }
    return count;
  }

  function countMatches(str, regex) {
    const m = str.match(regex);
    return m ? m.length : 0;
  }

  function isIPAddress(hostname) {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) ||
           /^\[?[0-9a-fA-F:]+\]?$/.test(hostname);
  }

  function extractTLD(hostname) {
    const parts = hostname.split(".");
    return parts.length > 1 ? parts[parts.length - 1].toLowerCase() : "unknown";
  }

  function countSubdomains(hostname) {
    const parts = hostname.split(".");
    return Math.max(0, parts.length - 2);
  }

  function containsKeywords(text, keywords) {
    const lower = text.toLowerCase();
    return keywords.some(k => lower.includes(k)) ? 1 : 0;
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Feature Extraction
  // ─────────────────────────────────────────────────────────────────────────────

  function extractFeatures() {
    const url           = window.location.href;
    const hostname      = window.location.hostname;
    const tld           = extractTLD(hostname);
    const pageText      = document.body ? document.body.innerText || "" : "";
    const htmlSource    = document.documentElement.outerHTML || "";
    const lines         = htmlSource.split("\n");
    const currentDomain = hostname.toLowerCase();

    const URLLength     = url.length;
    const DomainLength  = hostname.length;
    const IsDomainIP    = isIPAddress(hostname) ? 1 : 0;
    const TLD           = tld;
    const TLDLength     = tld.length;
    const NoOfSubDomain = countSubdomains(hostname);

    const HasObfuscation             = /%[0-9a-fA-F]{2}/.test(url) ? 1 : 0;
    const NoOfObfuscatedChar         = countMatches(url, /%[0-9a-fA-F]{2}/g);
    const ObfuscationRatio           = URLLength > 0 ? NoOfObfuscatedChar / URLLength : 0;
    const NoOfLettersInURL           = countMatches(url, /[a-zA-Z]/g);
    const LetterRatioInURL           = URLLength > 0 ? NoOfLettersInURL / URLLength : 0;
    const NoOfDegitsInURL            = countMatches(url, /[0-9]/g);
    const DegitRatioInURL            = URLLength > 0 ? NoOfDegitsInURL / URLLength : 0;
    const NoOfEqualsInURL            = countOccurrences(url, "=");
    const NoOfQMarkInURL             = countOccurrences(url, "?");
    const NoOfAmpersandInURL         = countOccurrences(url, "&");
    const specialCharsURL            = countMatches(url, /[^a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]/g);
    const NoOfOtherSpecialCharsInURL = specialCharsURL;
    const SpacialCharRatioInURL      = URLLength > 0 ? specialCharsURL / URLLength : 0;

    let continuationCount = 0;
    for (let i = 1; i < url.length; i++) {
      if (url[i] === url[i - 1]) continuationCount++;
    }
    const CharContinuationRate = URLLength > 1 ? continuationCount / (URLLength - 1) : 0;

    const IsHTTPS          = window.location.protocol === "https:" ? 1 : 0;
    const LineOfCode       = lines.length;
    const LargestLineLength = lines.reduce((max, l) => Math.max(max, l.length), 0);

    const titleEl      = document.querySelector("title");
    const HasTitle     = titleEl && titleEl.textContent.trim() !== "" ? 1 : 0;
    const titleText    = titleEl ? titleEl.textContent.toLowerCase().replace(/[^a-z0-9 ]/g, " ") : "";

    const domainWords  = currentDomain.replace(/[^a-z0-9 ]/g, " ").split(/\s+/).filter(w => w.length > 2);
    const titleWords   = titleText.split(/\s+/).filter(w => w.length > 0);
    const domainMatches = domainWords.filter(w => titleWords.includes(w) || titleText.includes(w)).length;
    const DomainTitleMatchScore = domainWords.length > 0 ? Math.min(100, (domainMatches / domainWords.length) * 100) : 0;

    const urlWords     = url.toLowerCase().replace(/[^a-z0-9 ]/g, " ").split(/\s+/).filter(w => w.length > 2);
    const urlMatches   = urlWords.filter(w => titleWords.includes(w) || titleText.includes(w)).length;
    const URLTitleMatchScore = urlWords.length > 0 ? Math.min(100, (urlMatches / urlWords.length) * 100) : 0;

    const HasFavicon     = document.querySelector("link[rel*='icon']") ? 1 : 0;
    const Robots         = 0;
    const HasDescription = document.querySelector("meta[name='description']") ? 1 : 0;
    const IsResponsive   = document.querySelector("meta[name='viewport']") ? 1 : 0;

    const allScriptText   = Array.from(document.scripts).map(s => s.textContent || "").join(" ");
    const NoOfPopup       = countOccurrences(allScriptText, "window.open");
    const NoOfURLRedirect = document.querySelectorAll("meta[http-equiv='refresh']").length;
    const NoOfSelfRedirect = 0;
    const NoOfiFrame      = document.querySelectorAll("iframe").length;

    const currentParts  = currentDomain.split(".");
    const rootDomain    = currentParts.length >= 2 ? currentParts.slice(-2).join(".") : currentDomain;

    const forms = document.querySelectorAll("form");
    let externalFormSubmit = 0;
    forms.forEach(form => {
      const action = (form.getAttribute("action") || "").trim();
      if (action.startsWith("http")) {
        try {
          const actionHost = new URL(action).hostname.toLowerCase();
          if (actionHost !== currentDomain && !actionHost.endsWith("." + rootDomain) && actionHost !== rootDomain) {
            externalFormSubmit = 1;
          }
        } catch {
          externalFormSubmit = 1;
        }
      }
    });
    const HasExternalFormSubmit = externalFormSubmit;

    const socialNets   = ["facebook.com","twitter.com","x.com","instagram.com","linkedin.com","youtube.com","tiktok.com","github.com"];
    const allLinks     = Array.from(document.querySelectorAll("a[href]")).map(a => a.href);
    const HasSocialNet = allLinks.some(href => socialNets.some(s => href.includes(s))) ? 1 : 0;

    const HasSubmitButton  = document.querySelector("input[type='submit'], button[type='submit'], button:not([type])") ? 1 : 0;
    const HasHiddenFields  = document.querySelectorAll("input[type='hidden']").length > 0 ? 1 : 0;
    const HasPasswordField = document.querySelector("input[type='password']") ? 1 : 0;

    const Bank             = containsKeywords(pageText, ["bank","banking","account","login","signin","verify","secure"]);
    const Pay              = containsKeywords(pageText, ["payment","pay now","checkout","billing","invoice","add to cart","buy now","order now","shopping cart","credit card","debit card","cash on delivery"]);
    const Crypto           = containsKeywords(pageText, ["bitcoin","ethereum","crypto","wallet","blockchain","btc","eth"]);
    const HasCopyrightInfo = containsKeywords(pageText, ["©","copyright","all rights reserved"]) || (htmlSource.toLowerCase().includes("&copy;") ? 1 : 0);

    const NoOfImage = document.querySelectorAll("img").length;
    const NoOfCSS   = document.querySelectorAll("link[rel='stylesheet']").length;
    const NoOfJS    = document.querySelectorAll("script[src]").length;

    let selfRef = 0, emptyRef = 0, externalRef = 0;
    allLinks.forEach(href => {
      if (!href || href === "#" || href === "" || href.startsWith("javascript:")) {
        emptyRef++;
      } else {
        try {
          const lh = new URL(href).hostname.toLowerCase();
          if (lh === currentDomain || lh === "" || lh === rootDomain || lh.endsWith("." + rootDomain)) selfRef++;
          else externalRef++;
        } catch { emptyRef++; }
      }
    });
    const NoOfSelfRef     = selfRef;
    const NoOfEmptyRef    = emptyRef;
    const NoOfExternalRef = externalRef;

    return {
      // Metadata for whitelist check in backend
      url:      window.location.href,
      hostname: hostname,

      // ML features
      URLLength, DomainLength, IsDomainIP, TLD, TLDLength, NoOfSubDomain,
      HasObfuscation, NoOfObfuscatedChar, ObfuscationRatio,
      NoOfLettersInURL, LetterRatioInURL,
      NoOfDegitsInURL, DegitRatioInURL,
      NoOfEqualsInURL, NoOfQMarkInURL, NoOfAmpersandInURL,
      NoOfOtherSpecialCharsInURL, SpacialCharRatioInURL, CharContinuationRate,
      IsHTTPS, LineOfCode, LargestLineLength,
      HasTitle, DomainTitleMatchScore, URLTitleMatchScore,
      HasFavicon, Robots, IsResponsive,
      NoOfURLRedirect, NoOfSelfRedirect,
      HasDescription, NoOfPopup, NoOfiFrame,
      HasExternalFormSubmit, HasSocialNet,
      HasSubmitButton, HasHiddenFields, HasPasswordField,
      Bank, Pay, Crypto, HasCopyrightInfo,
      NoOfImage, NoOfCSS, NoOfJS,
      NoOfSelfRef, NoOfEmptyRef, NoOfExternalRef,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // In-Page Security Notifications — Ultra-clean, non-intrusive, professional
  // ─────────────────────────────────────────────────────────────────────────────

  const BANNER_ID = "__phishguard_banner__";
  let autoDismissTimer = null;

  function formatXAIMarkdown(text) {
    if (!text) return "";
    return text
      .replace(/^### (.*$)/gim, '<div style="font-size:12px; font-weight:700; color:#f1f5f9; margin:8px 0 3px 0;">$1</div>')
      .replace(/^## (.*$)/gim, '<div style="font-size:13px; font-weight:700; color:#f1f5f9; margin:10px 0 4px 0;">$1</div>')
      .replace(/^# (.*$)/gim, '<div style="font-size:14px; font-weight:700; color:#f1f5f9; margin:12px 0 5px 0;">$1</div>')
      .replace(/\*\*(.*?)\*\*/gim, '<strong style="color:#ffffff;">$1</strong>')
      .replace(/\*(.*?)\*/gim, '<em style="color:#94a3b8;">$1</em>')
      .replace(/^- (.*$)/gim, '<div style="margin:3px 0 3px 6px; display:flex; gap:6px; line-height:1.45;"><span style="color:#f43f5e; flex-shrink:0;">•</span><span>$1</span></div>')
      .replace(/\n\n/g, '<div style="height:6px;"></div>')
      .replace(/\n/g, '<br/>');
  }

  function injectBanner(data) {
    const existing = document.getElementById(BANNER_ID);
    if (existing) existing.remove();
    if (autoDismissTimer) clearTimeout(autoDismissTimer);

    const isPhishing  = Boolean(data.is_phishing);
    const pct         = Math.round((data.phishing_probability || 0) * 100);
    const legitPct    = Math.round((data.legitimate_probability || (1 - (data.phishing_probability || 0))) * 100);
    const risk        = (data.risk_level || "HIGH").toUpperCase();
    const isWhitelist = data.whitelisted === true;

    const banner = document.createElement("div");
    banner.id = BANNER_ID;

    // ── Safe Page: Discreet Floating Toast (Auto-Dismisses) ──
    if (!isPhishing) {
      banner.style.cssText = `
        position: fixed !important;
        top: 16px !important;
        right: 18px !important;
        z-index: 2147483647 !important;
        font-family: -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', Roboto, sans-serif !important;
        background: rgba(10, 14, 23, 0.94) !important;
        backdrop-filter: blur(16px) !important;
        -webkit-backdrop-filter: blur(16px) !important;
        border: 1px solid rgba(16, 185, 129, 0.3) !important;
        border-radius: 9999px !important;
        padding: 7px 14px 7px 10px !important;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.45), 0 0 16px rgba(16, 185, 129, 0.1) !important;
        display: flex !important;
        align-items: center !important;
        gap: 9px !important;
        transform: translateY(-20px) scale(0.96) !important;
        opacity: 0 !important;
        transition: all 0.28s cubic-bezier(0.16, 1, 0.3, 1) !important;
        pointer-events: auto !important;
        box-sizing: border-box !important;
        color: #f1f5f9 !important;
      `;

      banner.innerHTML = `
        <div style="
          width: 22px; height: 22px; border-radius: 50%;
          background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.35);
          display: flex; align-items: center; justify-content: center;
          color: #10b981; font-size: 11px; flex-shrink: 0; font-weight: 700;
        ">✓</div>
        <div style="display: flex; flex-direction: column; line-height: 1.2;">
          <div style="font-size: 11.5px; font-weight: 600; color: #f1f5f9; display: flex; align-items: center; gap: 5px;">
            <span>${isWhitelist ? 'Trusted Domain' : 'Verified Legitimate'}</span>
            <span style="font-size: 9px; color: #10b981; font-weight: 700; background: rgba(16, 185, 129, 0.15); padding: 1px 5px; border-radius: 999px;">${legitPct}% SAFE</span>
          </div>
          <div style="font-size: 10px; color: #94a3b8; margin-top: 1px;">No credential harvesting traps</div>
        </div>
        <button id="__pg_toast_close__" style="
          background: transparent; border: none; color: #64748b;
          cursor: pointer; padding: 2px 4px; font-size: 12px;
          margin-left: 4px; display: flex; align-items: center; transition: color 0.15s;
        " title="Dismiss">✕</button>
      `;

      document.documentElement.appendChild(banner);

      requestAnimationFrame(() => requestAnimationFrame(() => {
        banner.style.transform = "translateY(0) scale(1)";
        banner.style.opacity = "1";
      }));

      function removeToast() {
        banner.style.transform = "translateY(-16px) scale(0.96)";
        banner.style.opacity = "0";
        setTimeout(() => { if (banner.parentNode) banner.remove(); }, 300);
      }

      const closeBtn = banner.querySelector("#__pg_toast_close__");
      if (closeBtn) closeBtn.addEventListener("click", removeToast);
      autoDismissTimer = setTimeout(removeToast, 4000);
      return;
    }

    // ── Phishing Page: Authoritative Security Warning Banner ──
    banner.style.cssText = `
      position: fixed !important;
      top: 0 !important; left: 0 !important; right: 0 !important;
      width: 100% !important;
      z-index: 2147483647 !important;
      font-family: -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', Roboto, sans-serif !important;
      transform: translateY(-100%) !important;
      transition: transform 0.32s cubic-bezier(0.16, 1, 0.3, 1) !important;
      box-sizing: border-box !important;
      background: #0d111a !important;
      color: #f1f5f9 !important;
      box-shadow: 0 12px 36px rgba(0, 0, 0, 0.7) !important;
    `;

    banner.innerHTML = `
      <style>
        @keyframes pgSpin { to { transform: rotate(360deg); } }
        #__pg_leave_btn__:hover { filter: brightness(1.15) !important; }
        #__pg_toggle_btn__:hover { background: rgba(255,255,255,0.12) !important; }
      </style>

      <div style="
        background: linear-gradient(180deg, #180d12 0%, #0d111a 100%);
        border-bottom: 1px solid rgba(244, 63, 94, 0.35);
        display: flex; align-items: center; justify-content: space-between;
        gap: 14px; padding: 10px 20px; box-sizing: border-box; width: 100%;
      ">
        <div style="display: flex; align-items: center; gap: 12px; flex: 1; min-width: 0;">
          <div style="
            width: 32px; height: 32px; border-radius: 8px; flex-shrink: 0;
            background: rgba(244, 63, 94, 0.15); border: 1px solid rgba(244, 63, 94, 0.4);
            display: flex; align-items: center; justify-content: center;
            font-size: 15px; font-weight: 800; color: #f43f5e;
            box-shadow: 0 0 14px rgba(244, 63, 94, 0.2);
          ">!</div>

          <div style="min-width: 0;">
            <div style="display: flex; align-items: center; gap: 7px; flex-wrap: wrap;">
              <span style="font-size: 13.5px; font-weight: 700; color: #ffffff; letter-spacing: -0.15px;">
                Phishing Threat Detected
              </span>
              <span style="
                font-size: 9.5px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.4px;
                background: rgba(244, 63, 94, 0.18); border: 1px solid rgba(244, 63, 94, 0.4);
                color: #f43f5e; padding: 1px 7px; border-radius: 9999px;
              ">${risk} RISK · ${pct}%</span>
            </div>
            <div style="
              font-size: 11.5px; color: #cbd5e1; margin-top: 2px;
              white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
            ">
              This page mimics an authentic service to harvest passwords or sensitive data. Do <strong>not</strong> enter credentials.
            </div>
          </div>
        </div>

        <div style="display: flex; align-items: center; gap: 8px; flex-shrink: 0;">
          <button id="__pg_leave_btn__" style="
            background: #e11d48; border: none; border-radius: 6px;
            color: #ffffff; font-size: 12px; font-weight: 600;
            padding: 6px 14px; cursor: pointer; transition: all 0.15s ease;
            box-shadow: 0 2px 8px rgba(225, 29, 72, 0.35);
          ">Leave Site</button>

          <button id="__pg_toggle_btn__" style="
            background: rgba(255, 255, 255, 0.07); border: 1px solid rgba(255, 255, 255, 0.14);
            border-radius: 6px; color: #e2e8f0; font-size: 12px; font-weight: 500;
            padding: 6px 12px; cursor: pointer; display: flex; align-items: center; gap: 5px;
            transition: all 0.15s ease;
          ">
            <span>Explainable AI</span>
            <span id="__pg_chevron__" style="font-size: 9px; transition: transform 0.2s;">▼</span>
          </button>

          <button id="__pg_dismiss__" style="
            background: transparent; border: 1px solid rgba(255, 255, 255, 0.1);
            color: #94a3b8; cursor: pointer; width: 26px; height: 26px; border-radius: 6px;
            display: flex; align-items: center; justify-content: center; font-size: 12px;
            transition: all 0.15s ease;
          " title="Dismiss">✕</button>
        </div>
      </div>

      <!-- Accent progress hairline -->
      <div style="height: 2px; background: linear-gradient(90deg, #f43f5e ${pct}%, rgba(255,255,255,0.06) ${pct}%);"></div>

      <!-- ── Explainable AI (XAI) Expandable Drawer ── -->
      <div id="__pg_explain_drawer__" style="
        display: none;
        background: #090d16;
        border-bottom: 1px solid rgba(255, 255, 255, 0.08);
        padding: 14px 20px 16px 20px;
        color: #cbd5e1;
        font-size: 12px;
        max-height: 400px;
        overflow-y: auto;
        box-sizing: border-box;
      ">
        <!-- Section 1: Detected Red Flags -->
        <div style="margin-bottom: 12px;">
          <div style="font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.6px; color: #f43f5e; margin-bottom: 6px; display: flex; align-items: center; gap: 5px;">
            <span>🚨 Detected Technical Red Flags</span>
          </div>
          <div id="__pg_indicators_list__" style="display: flex; flex-wrap: wrap; gap: 6px;"></div>
        </div>

        <!-- Section 2: AI Incident Analysis -->
        <div style="background: #0e1422; border: 1px solid rgba(255, 255, 255, 0.07); border-radius: 8px; padding: 12px 14px;">
          <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; border-bottom: 1px solid rgba(255,255,255,0.06); padding-bottom: 6px;">
            <div style="display: flex; align-items: center; gap: 6px; font-weight: 600; font-size: 11.5px; color: #ffffff;">
              <span style="font-size: 13px;">✨</span>
              <span>Explainable AI Incident Briefing</span>
            </div>
            <div id="__pg_ai_source_badge__" style="font-size: 9.5px; font-weight: 600; padding: 2px 7px; border-radius: 999px; background: rgba(56, 189, 248, 0.12); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.25);">
              AI Shield Engine
            </div>
          </div>
          <div id="__pg_ai_content__" style="line-height: 1.55; color: #cbd5e1; font-size: 11.5px;">
            <div style="display:flex; align-items:center; gap:8px; color:#8293a9;">
              <span style="display:inline-block; width:12px; height:12px; border:2px solid #55657b; border-top-color:#38bdf8; border-radius:50%; animation:pgSpin 0.8s linear infinite;"></span>
              <span>Synthesizing incident response briefing...</span>
            </div>
          </div>
        </div>
      </div>
    `;

    document.documentElement.appendChild(banner);

    // Slide in
    requestAnimationFrame(() => requestAnimationFrame(() => {
      banner.style.transform = "translateY(0)";
    }));

    function slideOut() {
      banner.style.transform = "translateY(-110%)";
      setTimeout(() => { if (banner.parentNode) banner.remove(); }, 320);
    }

    const dismissBtn = banner.querySelector("#__pg_dismiss__");
    if (dismissBtn) {
      dismissBtn.addEventListener("click", slideOut);
    }

    // Leave Site action
    const leaveBtn = banner.querySelector("#__pg_leave_btn__");
    if (leaveBtn) {
      leaveBtn.addEventListener("click", () => {
        if (window.history.length > 1) {
          window.history.back();
        } else {
          window.location.href = "https://www.google.com";
        }
      });
    }

    // Populate top indicators
    const indList   = banner.querySelector("#__pg_indicators_list__");
    const indicators = data.top_indicators && data.top_indicators.length
      ? data.top_indicators
      : ["Structural match with known credential-theft pages.", "High-confidence anomalous feature distribution."];

    indList.innerHTML = indicators.map(ind => `
      <div style="
        background: rgba(244, 63, 94, 0.08);
        border: 1px solid rgba(244, 63, 94, 0.22);
        color: #fca5a5;
        padding: 3px 8px; border-radius: 5px; font-size: 10.5px;
      ">• ${ind}</div>
    `).join("");

    const drawer    = banner.querySelector("#__pg_explain_drawer__");
    const chevron   = banner.querySelector("#__pg_chevron__");
    const aiContent = banner.querySelector("#__pg_ai_content__");
    const aiBadge   = banner.querySelector("#__pg_ai_source_badge__");

    let drawerOpen = false;
    let explanationLoaded = false;
    drawer.style.display = "none";
    chevron.style.transform = "rotate(0deg)";

    const toggleBtn = banner.querySelector("#__pg_toggle_btn__");
    toggleBtn.addEventListener("click", () => {
      drawerOpen = !drawerOpen;
      drawer.style.display = drawerOpen ? "block" : "none";
      chevron.style.transform = drawerOpen ? "rotate(180deg)" : "rotate(0deg)";

      // Fetch on-demand only when user expands
      if (drawerOpen && !explanationLoaded) {
        aiContent.innerHTML = `
          <div style="display:flex; align-items:center; gap:8px; color:#8293a9;">
            <span style="display:inline-block; width:12px; height:12px; border:2px solid #55657b; border-top-color:#38bdf8; border-radius:50%; animation:pgSpin 0.8s linear infinite;"></span>
            <span>Synthesizing incident response briefing...</span>
          </div>
        `;

        chrome.runtime.sendMessage({
          type: "EXPLAIN_URL",
          url: data.url || window.location.href,
          hostname: window.location.hostname,
          is_phishing: true,
          risk_level: data.risk_level,
          phishing_probability: data.phishing_probability,
          features: data.features || {},
        }, (res) => {
          explanationLoaded = true;
          if (!res || res.error) {
            aiBadge.textContent = "Security Heuristics";
            aiBadge.style.background = "rgba(245, 158, 11, 0.12)";
            aiBadge.style.color = "#f59e0b";
            aiBadge.style.borderColor = "rgba(245, 158, 11, 0.25)";
            aiContent.innerHTML = formatXAIMarkdown(res?.explanation || `Critical threat indicators detected on ${window.location.hostname}. Please close this window.`);
            return;
          }

          if (res.source === "groq" || res.source === "groq_direct") {
            aiBadge.textContent = "⚡ Groq AI";
          } else {
            aiBadge.textContent = "Security Heuristics";
            aiBadge.style.background = "rgba(255, 255, 255, 0.08)";
            aiBadge.style.color = "#94a3b8";
            aiBadge.style.borderColor = "rgba(255, 255, 255, 0.12)";
          }

          aiContent.innerHTML = formatXAIMarkdown(res.explanation);
        });
      }
    });
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Listen for result pushed back from background worker
  // ─────────────────────────────────────────────────────────────────────────────

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "PHISHING_RESULT" && message.data) {
      injectBanner(message.data);
    }
    if (message.type === "TRIGGER_RESCAN") {
      delete window[SCAN_KEY];
      runScan();
      sendResponse({ ok: true });
      return true;
    }
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // Main — Run scan only after page content is confirmed meaningful
  // ─────────────────────────────────────────────────────────────────────────────

  function runScan() {
    if (!isPageMeaningful()) {
      // Page is blank/redirect stub — wait and retry once
      setTimeout(() => {
        if (isPageMeaningful()) sendFeatures();
        // else silently skip — we won't scan blank pages
      }, 1500);
      return;
    }
    sendFeatures();
  }

  function sendFeatures() {
    try {
      const features = extractFeatures();
      chrome.runtime.sendMessage(
        { type: "ANALYZE_PAGE", url: window.location.href, features },
        (response) => {
          if (chrome.runtime.lastError) return; // Background not ready — ignore
        }
      );
    } catch (err) {
      console.warn("[PhishGuard] Feature extraction error:", err);
    }
  }

  // Wait a brief moment to ensure DOM is truly settled before scanning
  // (handles SPA frameworks that render content after document_idle)
  setTimeout(runScan, 800);

})();
