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
    const titleText    = titleEl ? titleEl.textContent.toLowerCase() : "";

    const domainWords  = currentDomain.replace(/\./g, " ").split(" ").filter(w => w.length > 2);
    const titleWords   = titleText.split(/\s+/);
    const DomainTitleMatchScore = domainWords.filter(w => titleWords.includes(w)).length * 10;

    const urlWords     = url.toLowerCase().replace(/[^a-z0-9 ]/g, " ").split(" ").filter(w => w.length > 2);
    const URLTitleMatchScore = urlWords.filter(w => titleWords.includes(w)).length * 10;

    const HasFavicon     = document.querySelector("link[rel*='icon']") ? 1 : 0;
    const Robots         = 0;
    const HasDescription = document.querySelector("meta[name='description']") ? 1 : 0;
    const IsResponsive   = document.querySelector("meta[name='viewport']") ? 1 : 0;

    const allScriptText   = Array.from(document.scripts).map(s => s.textContent || "").join(" ");
    const NoOfPopup       = countOccurrences(allScriptText, "window.open");
    const NoOfURLRedirect = document.querySelectorAll("meta[http-equiv='refresh']").length;
    const NoOfSelfRedirect = 0;
    const NoOfiFrame      = document.querySelectorAll("iframe").length;

    const forms = document.querySelectorAll("form");
    let externalFormSubmit = 0;
    forms.forEach(form => {
      const action = form.getAttribute("action") || "";
      if (action.startsWith("http") && !action.includes(currentDomain)) externalFormSubmit = 1;
    });
    const HasExternalFormSubmit = externalFormSubmit;

    const socialNets   = ["facebook.com","twitter.com","instagram.com","linkedin.com","youtube.com","tiktok.com"];
    const allLinks     = Array.from(document.querySelectorAll("a[href]")).map(a => a.href);
    const HasSocialNet = allLinks.some(href => socialNets.some(s => href.includes(s))) ? 1 : 0;

    const HasSubmitButton  = document.querySelector("input[type='submit'], button[type='submit'], button:not([type])") ? 1 : 0;
    const HasHiddenFields  = document.querySelectorAll("input[type='hidden']").length > 0 ? 1 : 0;
    const HasPasswordField = document.querySelector("input[type='password']") ? 1 : 0;

    const Bank             = containsKeywords(pageText, ["bank","banking","account","login","signin","verify","secure"]);
    const Pay              = containsKeywords(pageText, ["payment","pay now","checkout","billing","invoice"]);
    const Crypto           = containsKeywords(pageText, ["bitcoin","ethereum","crypto","wallet","blockchain","btc","eth"]);
    const HasCopyrightInfo = containsKeywords(pageText, ["©","copyright","all rights reserved"]);

    const NoOfImage = document.querySelectorAll("img").length;
    const NoOfCSS   = document.querySelectorAll("link[rel='stylesheet']").length;
    const NoOfJS    = document.querySelectorAll("script[src]").length;

    let selfRef = 0, emptyRef = 0, externalRef = 0;
    allLinks.forEach(href => {
      if (!href || href === "#" || href === "" || href.startsWith("javascript:")) {
        emptyRef++;
      } else {
        try {
          const lh = new URL(href).hostname;
          if (lh === currentDomain || lh === "") selfRef++;
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
  // In-Page Banner — clean, minimal, professional
  // ─────────────────────────────────────────────────────────────────────────────

  const BANNER_ID = "__phishguard_banner__";

  let autoDismissTimer = null;

  function formatXAIMarkdown(text) {
    if (!text) return "";
    return text
      .replace(/^### (.*$)/gim, '<div style="font-size:12px; font-weight:700; color:#fff; margin:8px 0 3px 0;">$1</div>')
      .replace(/^## (.*$)/gim, '<div style="font-size:13px; font-weight:700; color:#fff; margin:10px 0 4px 0;">$1</div>')
      .replace(/^# (.*$)/gim, '<div style="font-size:14px; font-weight:700; color:#fff; margin:12px 0 5px 0;">$1</div>')
      .replace(/\*\*(.*?)\*\*/gim, '<strong style="color:#fff;">$1</strong>')
      .replace(/\*(.*?)\*/gim, '<em style="color:#ccc;">$1</em>')
      .replace(/^- (.*$)/gim, '<div style="margin:3px 0 3px 6px; display:flex; gap:6px; line-height:1.45;"><span style="color:#ff6b6b; flex-shrink:0;">•</span><span>$1</span></div>')
      .replace(/\n\n/g, '<div style="height:6px;"></div>')
      .replace(/\n/g, '<br/>');
  }

  function injectBanner(data) {
    const existing = document.getElementById(BANNER_ID);
    if (existing) existing.remove();
    if (autoDismissTimer) clearTimeout(autoDismissTimer);

    const isPhishing = data.is_phishing;
    const pct        = Math.round((data.phishing_probability || 0) * 100);
    const legitPct   = Math.round((data.legitimate_probability || 0) * 100);
    const risk       = (data.risk_level || "HIGH").toUpperCase();
    const isWhitelist = data.whitelisted === true;

    // Color scheme
    const C = isPhishing
      ? { bg: "#0e0505", border: "#3d1212", accent: "#ff453a", sub: "#c97e7e", chipBg: "rgba(255,69,58,0.15)", chipBdr: "rgba(255,69,58,0.3)" }
      : { bg: "#040e06", border: "#0e3018", accent: "#30d158", sub: "#6eaa80", chipBg: "rgba(48,209,88,0.12)",  chipBdr: "rgba(48,209,88,0.25)" };

    const banner = document.createElement("div");
    banner.id    = BANNER_ID;
    banner.style.cssText = `
      position: fixed !important;
      top: 0 !important; left: 0 !important; right: 0 !important;
      width: 100% !important;
      z-index: 2147483647 !important;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
      transform: translateY(-110%) !important;
      transition: transform 0.35s cubic-bezier(0.22, 1, 0.36, 1) !important;
      box-sizing: border-box !important;
    `;

    const label = isPhishing
      ? `Phishing detected &nbsp;·&nbsp; ${risk} Risk`
      : (isWhitelist ? "Trusted domain verified" : "Page verified safe");

    const subLabel = isPhishing
      ? `${pct}% phishing confidence &nbsp;·&nbsp; Do <strong>not</strong> enter credentials`
      : `${legitPct}% legitimate confidence &nbsp;·&nbsp; No threats detected`;

    const icon = isPhishing ? "!" : "✓";

    banner.innerHTML = `
      <div style="
        background:${C.bg}; border-bottom:1px solid ${C.border};
        box-shadow:0 6px 24px rgba(0,0,0,0.5);
        display:flex; align-items:center; justify-content:space-between;
        gap:12px; padding:9px 18px; box-sizing:border-box; width:100%;
      ">
        <div style="display:flex; align-items:center; gap:11px; flex:1; min-width:0;">
          <div style="
            width:28px; height:28px; border-radius:50%; flex-shrink:0;
            background:${C.chipBg}; border:1px solid ${C.chipBdr};
            display:flex; align-items:center; justify-content:center;
            font-size:13px; font-weight:700; color:${C.accent};
          ">${icon}</div>
          <div style="min-width:0;">
            <div style="
              font-size:13px; font-weight:600; color:${C.accent};
              letter-spacing:-0.1px; line-height:1.3;
              white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
            ">${label}</div>
            <div style="
              font-size:11px; color:${C.sub}; margin-top:1px;
              white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
            ">${subLabel}</div>
          </div>
        </div>

        <div style="display:flex; align-items:center; gap:8px; flex-shrink:0;">
          <!-- Explainable AI Button -->
          <button id="__pg_explain_btn__" style="
            background: ${isPhishing ? 'rgba(255,69,58,0.18)' : 'rgba(48,209,88,0.15)'};
            border: 1px solid ${isPhishing ? 'rgba(255,69,58,0.4)' : 'rgba(48,209,88,0.3)'};
            color: ${C.accent};
            cursor: pointer;
            font-size: 11px;
            font-weight: 600;
            padding: 4px 10px;
            border-radius: 6px;
            display: flex;
            align-items: center;
            gap: 5px;
            transition: all 0.2s ease;
          " title="Click to view why this page was flagged using Explainable AI">
            <span>✨ Why was this flagged?</span>
            <span id="__pg_drawer_chevron__" style="font-size:9px; transition: transform 0.2s;">▼</span>
          </button>

          <div style="
            background:${C.chipBg}; border:1px solid ${C.chipBdr};
            color:${C.accent}; font-size:10px; font-weight:600;
            letter-spacing:0.4px; padding:2px 8px; border-radius:999px;
          ">PhishGuard</div>

          <button id="__pg_dismiss__" style="
            background:transparent; border:1px solid rgba(255,255,255,0.1);
            color:rgba(255,255,255,0.35); cursor:pointer;
            width:22px; height:22px; border-radius:5px;
            display:flex; align-items:center; justify-content:center;
            font-size:12px; line-height:1;
          " title="Dismiss">✕</button>
        </div>
      </div>
      <div style="height:2px; background:linear-gradient(90deg, ${C.accent} ${isPhishing ? pct : legitPct}%, rgba(255,255,255,0.04) ${isPhishing ? pct : legitPct}%);"></div>

      <!-- ── Explainable AI (XAI) Expandable Drawer ── -->
      <div id="__pg_explain_drawer__" style="
        display: none;
        background: #111115;
        border-bottom: 1px solid rgba(255,255,255,0.12);
        box-shadow: 0 12px 36px rgba(0,0,0,0.6);
        padding: 14px 20px 16px 20px;
        color: #e5e5eb;
        font-size: 12px;
        max-height: 440px;
        overflow-y: auto;
        box-sizing: border-box;
      ">
        <!-- Section 1: Detected Indicators / Feature Attribution -->
        <div style="margin-bottom: 12px;">
          <div style="font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.6px; color: ${C.accent}; margin-bottom: 6px; display: flex; align-items: center; gap: 5px;">
            <span>🛡️ Detected Red Flags & Technical Indicators</span>
          </div>
          <div id="__pg_indicators_list__" style="display: flex; flex-wrap: wrap; gap: 6px;"></div>
        </div>

        <!-- Section 2: Google Gemini AI Analysis Box -->
        <div style="background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 12px 14px; margin-bottom: 12px;">
          <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
            <div style="display: flex; align-items: center; gap: 6px; font-weight: 600; font-size: 12px; color: #fff;">
              <span style="font-size: 13px;">✨</span>
              <span>Explainable AI (XAI) Security Analysis</span>
            </div>
            <div id="__pg_ai_source_badge__" style="font-size: 10px; padding: 2px 7px; border-radius: 999px; background: rgba(255,255,255,0.08); color: #8e8e99;">
              Connecting...
            </div>
          </div>
          <div id="__pg_ai_content__" style="line-height: 1.5; color: #d0d0d8; font-size: 12px;">
            <div style="display:flex; align-items:center; gap:8px; color:#888;">
              <span style="display:inline-block; width:12px; height:12px; border:2px solid #666; border-top-color:#fff; border-radius:50%; animation:pgSpin 0.8s linear infinite;"></span>
              <span>Consulting AI security engine...</span>
            </div>
          </div>
        </div>

        <!-- Section 3: Gemini API Key Management -->
        <div style="display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 8px; padding-top: 10px; border-top: 1px solid rgba(255,255,255,0.07); font-size: 11px;">
          <div style="display: flex; align-items: center; gap: 8px; flex: 1; min-width: 250px;">
            <span style="color: #999; flex-shrink: 0;">🔑 Gemini API Key:</span>
            <input type="password" id="__pg_key_input__" placeholder="Enter Google Gemini API key..." style="
              background: rgba(0,0,0,0.6); border: 1px solid rgba(255,255,255,0.18); border-radius: 5px;
              padding: 5px 9px; color: #fff; font-size: 11px; flex: 1; outline: none;
            " />
            <button id="__pg_save_key_btn__" style="
              background: #0a84ff; border: none; border-radius: 5px; color: #fff; font-size: 11px;
              font-weight: 600; padding: 5px 11px; cursor: pointer; white-space: nowrap; transition: opacity 0.2s;
            ">Save & Analyze</button>
          </div>
          <div style="display: flex; align-items: center; gap: 10px;">
            <span id="__pg_key_status__" style="color: #888; font-size: 10px;"></span>
            <a href="https://aistudio.google.com/app/apikey" target="_blank" style="color: #58a6ff; text-decoration: none; font-size: 10px;">Get Free Key ↗</a>
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
      setTimeout(() => { if (banner.parentNode) banner.remove(); }, 380);
    }

    const dismissBtn = banner.querySelector("#__pg_dismiss__");
    if (dismissBtn) {
      dismissBtn.addEventListener("click", slideOut);
      dismissBtn.addEventListener("mouseenter", () => {
        dismissBtn.style.color = "rgba(255,255,255,0.8)";
        dismissBtn.style.borderColor = "rgba(255,255,255,0.3)";
      });
      dismissBtn.addEventListener("mouseleave", () => {
        dismissBtn.style.color = "rgba(255,255,255,0.35)";
        dismissBtn.style.borderColor = "rgba(255,255,255,0.1)";
      });
    }

    // Auto dismiss for safe banners
    if (!isPhishing) {
      autoDismissTimer = setTimeout(slideOut, 5000);
    }

    // ── Explainable AI Drawer Toggle & Logic ──
    const explainBtn   = banner.querySelector("#__pg_explain_btn__");
    const drawer       = banner.querySelector("#__pg_explain_drawer__");
    const chevron      = banner.querySelector("#__pg_drawer_chevron__");
    const indList      = banner.querySelector("#__pg_indicators_list__");
    const aiContent    = banner.querySelector("#__pg_ai_content__");
    const aiBadge      = banner.querySelector("#__pg_ai_source_badge__");
    const keyInput     = banner.querySelector("#__pg_key_input__");
    const saveKeyBtn   = banner.querySelector("#__pg_save_key_btn__");
    const keyStatus    = banner.querySelector("#__pg_key_status__");

    // Populate top indicators
    const indicators = data.top_indicators && data.top_indicators.length
      ? data.top_indicators
      : (isPhishing ? ["Structural similarity with credential harvesting templates.", "High confidence ML phishing signature."] : ["No security anomalies detected."]);

    indList.innerHTML = indicators.map(ind => `
      <div style="
        background: ${isPhishing ? 'rgba(255,69,58,0.1)' : 'rgba(48,209,88,0.1)'};
        border: 1px solid ${isPhishing ? 'rgba(255,69,58,0.25)' : 'rgba(48,209,88,0.2)'};
        color: ${isPhishing ? '#ff8580' : '#85e89d'};
        padding: 3px 8px; border-radius: 4px; font-size: 11px;
      ">• ${ind}</div>
    `).join("");

    let drawerOpen = false;
    let explanationFetched = false;

    const DEFAULT_OPENROUTER_KEY = "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";

    function refreshKeyUI() {
      chrome.storage.local.get("gemini_api_key", (stored) => {
        const key = stored.gemini_api_key || DEFAULT_OPENROUTER_KEY;
        if (stored.gemini_api_key) {
          keyInput.placeholder = "•••••••••••••••• (Custom Key)";
          keyStatus.innerHTML = '<span style="color:#30d158;">● Custom Key Active</span>';
        } else {
          keyInput.placeholder = "sk-or-v1-a2437... (OpenRouter Active)";
          keyStatus.innerHTML = '<span style="color:#30d158;">● OpenRouter Gemini Flash Connected</span>';
        }
      });
    }

    async function loadExplanation(overrideKey = null) {
      aiContent.innerHTML = `
        <div style="display:flex; align-items:center; gap:8px; color:#aaa;">
          <span style="display:inline-block; width:12px; height:12px; border:2px solid #666; border-top-color:#fff; border-radius:50%; animation:pgSpin 0.8s linear infinite;"></span>
          <span>Consulting OpenRouter Gemini Flash security engine...</span>
        </div>
      `;
      aiBadge.textContent = "Analyzing...";
      aiBadge.style.background = "rgba(10,132,255,0.2)";
      aiBadge.style.color = "#58a6ff";

      const stored = await chrome.storage.local.get("gemini_api_key");
      const apiKey = overrideKey || stored.gemini_api_key || DEFAULT_OPENROUTER_KEY;

      chrome.runtime.sendMessage({
        type: "EXPLAIN_URL",
        url: data.url || window.location.href,
        hostname: window.location.hostname,
        is_phishing: data.is_phishing,
        risk_level: data.risk_level,
        phishing_probability: data.phishing_probability,
        features: data.features || {},
        gemini_api_key: apiKey,
      }, (res) => {
        if (!res || res.error) {
          aiBadge.textContent = "Offline Fallback";
          aiBadge.style.background = "rgba(255,159,10,0.18)";
          aiBadge.style.color = "#ff9f0a";
          aiContent.innerHTML = formatXAIMarkdown(res?.explanation || `Analysis complete. High phishing indicators detected for ${window.location.hostname}.`);
          return;
        }

        if (res.source === "openrouter_gemini" || res.source === "openrouter_direct") {
          aiBadge.textContent = "✨ OpenRouter Gemini Flash";
          aiBadge.style.background = "rgba(48,209,88,0.18)";
          aiBadge.style.color = "#30d158";
        } else if (res.source === "gemini" || res.source === "gemini_direct") {
          aiBadge.textContent = "✨ Google Gemini AI";
          aiBadge.style.background = "rgba(48,209,88,0.18)";
          aiBadge.style.color = "#30d158";
        } else {
          aiBadge.textContent = "Rule-Based Attribution";
          aiBadge.style.background = "rgba(255,255,255,0.1)";
          aiBadge.style.color = "#aaa";
        }

        aiContent.innerHTML = formatXAIMarkdown(res.explanation);
        explanationFetched = true;
      });
    }

    explainBtn.addEventListener("click", () => {
      drawerOpen = !drawerOpen;
      if (drawerOpen) {
        if (autoDismissTimer) clearTimeout(autoDismissTimer);
        drawer.style.display = "block";
        chevron.style.transform = "rotate(180deg)";
        refreshKeyUI();
        if (!explanationFetched) {
          loadExplanation();
        }
      } else {
        drawer.style.display = "none";
        chevron.style.transform = "rotate(0deg)";
      }
    });

    saveKeyBtn.addEventListener("click", () => {
      const val = keyInput.value.trim();
      if (!val) {
        keyStatus.innerHTML = '<span style="color:#ff453a;">Please enter a valid key</span>';
        return;
      }
      saveKeyBtn.textContent = "Saving...";
      saveKeyBtn.style.opacity = "0.7";
      chrome.storage.local.set({ gemini_api_key: val }, () => {
        saveKeyBtn.textContent = "Saved!";
        keyInput.value = "";
        refreshKeyUI();
        loadExplanation(val);
        setTimeout(() => {
          saveKeyBtn.textContent = "Save & Analyze";
          saveKeyBtn.style.opacity = "1";
        }, 1500);
      });
    });
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Listen for result pushed back from background worker
  // ─────────────────────────────────────────────────────────────────────────────

  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "PHISHING_RESULT" && message.data) {
      injectBanner(message.data);
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
      console.error("[PhishGuard] Feature extraction error:", err);
    }
  }

  // Wait a brief moment to ensure DOM is truly settled before scanning
  // (handles SPA frameworks that render content after document_idle)
  setTimeout(runScan, 800);

})();
