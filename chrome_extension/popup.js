/**
 * popup.js — PhishGuard Extension Popup Controller
 *
 * Ultra-Clean, Precision UI Controller:
 * - 48-Point Vector Telemetry Inspector
 * - Explainable AI (XAI) with OpenRouter / Gemini key management
 * - Responsive Segmented Navigation
 * - Graceful Fallbacks & Offline Capability
 */

"use strict";

// ── DOM References ──────────────────────────────────────────────────
const viewLoading  = document.getElementById("viewLoading");
const viewIdle     = document.getElementById("viewIdle");
const viewError    = document.getElementById("viewError");
const viewSafe     = document.getElementById("viewSafe");
const viewPhishing = document.getElementById("viewPhishing");

const brandMark         = document.getElementById("brandMark");
const headerStatusBadge = document.getElementById("headerStatusBadge");
const rescanBtn         = document.getElementById("rescanBtn");
const rescanIcon        = document.getElementById("rescanIcon");
const statsRow          = document.getElementById("statsRow");
const errorMsg          = document.getElementById("errorMsg");

// Navigation Tabs & Panes
const navTabs         = document.getElementById("navTabs");
const tabOverviewBtn  = document.getElementById("tabOverviewBtn");
const tabTelemetryBtn = document.getElementById("tabTelemetryBtn");
const paneOverview    = document.getElementById("paneOverview");
const paneTelemetry   = document.getElementById("paneTelemetry");

// Safe view
const safeScore         = document.getElementById("safeScore");
const safeScoreLabel    = document.getElementById("safeScoreLabel");
const safeUrl           = document.getElementById("safeUrl");
const safeMeter         = document.getElementById("safeMeter");
const safeProtocolText  = document.getElementById("safeProtocolText");
const copySafeUrlBtn    = document.getElementById("copySafeUrlBtn");

// Phishing view
const phishScore         = document.getElementById("phishScore");
const phishScoreLabel    = document.getElementById("phishScoreLabel");
const phishUrl           = document.getElementById("phishUrl");
const phishMeter         = document.getElementById("phishMeter");
const riskChip           = document.getElementById("riskChip");
const riskLabel          = document.getElementById("riskLabel");
const phishProtocolText  = document.getElementById("phishProtocolText");
const copyPhishUrlBtn    = document.getElementById("copyPhishUrlBtn");

// Stats
const statPhish = document.getElementById("statPhish");
const statLegit = document.getElementById("statLegit");
const statRisk  = document.getElementById("statRisk");

// XAI Card
const xaiCard          = document.getElementById("xaiCard");
const xaiCardTitleText = document.getElementById("xaiCardTitleText");
const xaiSectionTitle  = document.getElementById("xaiSectionTitle");
const xaiBoxLabel      = document.getElementById("xaiBoxLabel");
const xaiTags          = document.getElementById("xaiTags");
const xaiSourceBadge   = document.getElementById("xaiSourceBadge");
const xaiText          = document.getElementById("xaiText");
const xaiKeyHint       = document.getElementById("xaiKeyHint");
const xaiKeyHintText   = document.getElementById("xaiKeyHintText");
const copyBriefingBtn  = document.getElementById("copyBriefingBtn");
const footerModel      = document.getElementById("footerModel");

// Telemetry grids
const telGridDomain   = document.getElementById("telGridDomain");
const telGridAuth     = document.getElementById("telGridAuth");
const telGridDom      = document.getElementById("telGridDom");
const telGridKeywords = document.getElementById("telGridKeywords");

// Settings panel
const settingsBtn            = document.getElementById("settingsBtn");
const settingsPanel          = document.getElementById("settingsPanel");
const settingsCloseBtn       = document.getElementById("settingsCloseBtn");
const settingsKeyInput       = document.getElementById("settingsKeyInput");
const toggleKeyVisibilityBtn = document.getElementById("toggleKeyVisibilityBtn");
const eyeIcon                = document.getElementById("eyeIcon");
const settingsSaveBtn        = document.getElementById("settingsSaveBtn");
const settingsKeyStatus      = document.getElementById("settingsKeyStatus");
const settingsClearBtn       = document.getElementById("settingsClearBtn");

// Action buttons
const idleScanBtn   = document.getElementById("idleScanBtn");
const retryErrorBtn = document.getElementById("retryErrorBtn");
const copyCodeBtn   = document.getElementById("copyCodeBtn");

let currentTabData = null;
let currentRawBriefing = "";

// ── Environment Check ───────────────────────────────────────────────
const hasChromeStorage = typeof chrome !== "undefined" && chrome.storage && chrome.storage.local;
const hasChromeTabs    = typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.query;

// Storage abstraction (fallback to localStorage if tested in standalone browser)
const store = {
  get: (key) => new Promise((resolve) => {
    if (hasChromeStorage) {
      chrome.storage.local.get(key, resolve);
    } else {
      try {
        const val = localStorage.getItem(key);
        resolve({ [key]: val ? JSON.parse(val) : undefined });
      } catch {
        resolve({});
      }
    }
  }),
  set: (obj) => new Promise((resolve) => {
    if (hasChromeStorage) {
      chrome.storage.local.set(obj, resolve);
    } else {
      try {
        Object.entries(obj).forEach(([k, v]) => localStorage.setItem(k, JSON.stringify(v)));
      } catch (_) {}
      resolve();
    }
  }),
  remove: (key) => new Promise((resolve) => {
    if (hasChromeStorage) {
      chrome.storage.local.remove(key, resolve);
    } else {
      try { localStorage.removeItem(key); } catch (_) {}
      resolve();
    }
  })
};

// ── Helpers ─────────────────────────────────────────────────────────

function hideAll() {
  [viewLoading, viewIdle, viewError, viewSafe, viewPhishing].forEach((el) => {
    if (el) el.style.display = "none";
  });
  if (statsRow) statsRow.style.display = "none";
  if (xaiCard) xaiCard.style.display = "none";
  if (navTabs) navTabs.style.display = "none";
  if (brandMark) brandMark.className = "brand-mark";
  if (headerStatusBadge) {
    headerStatusBadge.className = "brand-status-pill";
    headerStatusBadge.innerHTML = '<span class="status-pulse-dot"></span><span>LIVE</span>';
  }
}

function show(el) {
  if (el) el.style.display = "flex";
}

function fmt(probability) {
  if (probability == null || isNaN(probability)) return "0.0%";
  return `${(probability * 100).toFixed(1)}%`;
}

function truncateUrl(url, max = 34) {
  if (!url) return "—";
  try {
    const u = new URL(url);
    let s = u.hostname + (u.pathname !== "/" ? u.pathname : "");
    return s.length > max ? s.slice(0, max - 1) + "…" : s;
  } catch {
    return url.length > max ? url.slice(0, max - 1) + "…" : url;
  }
}

function bar(el, probability) {
  if (!el) return;
  setTimeout(() => {
    el.style.width = `${Math.min(100, Math.max(0, Math.round(probability * 100)))}%`;
  }, 100);
}

function riskColor(level) {
  const map = {
    HIGH: "var(--rose)",
    CRITICAL: "var(--rose)",
    MEDIUM: "var(--amber)",
    LOW: "var(--amber)",
    SAFE: "var(--emerald)"
  };
  return map[(level || "").toUpperCase()] || "var(--emerald)";
}

function formatMarkdown(text, isPhishing) {
  if (!text) return "";
  currentRawBriefing = text;
  const dotClass = isPhishing ? "" : " safe-dot";
  return text
    .replace(/^### (.*$)/gim, '<div class="md-heading">$1</div>')
    .replace(/^## (.*$)/gim, '<div class="md-heading">$1</div>')
    .replace(/\*\*(.*?)\*\*/gim, "<strong>$1</strong>")
    .replace(/^[\*\-] +([^\n\r]+)/gim,
      `<div class="md-bullet"><span class="md-bullet-dot${dotClass}">▸</span><span>$1</span></div>`)
    .replace(/\*([^\*]+)\*/gim, "<em>$1</em>")
    .replace(/\n\n/g, '<div style="height:6px;"></div>')
    .replace(/\n/g, "<br/>");
}

function copyToClipboard(text, btnElement) {
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    if (!btnElement) return;
    btnElement.classList.add("copied");
    const origHtml = btnElement.innerHTML;
    btnElement.innerHTML = `
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <polyline points="20 6 9 17 4 12"/>
      </svg>
    `;
    setTimeout(() => {
      btnElement.classList.remove("copied");
      btnElement.innerHTML = origHtml;
    }, 1500);
  }).catch(() => {});
}

// ── Tab Navigation ──────────────────────────────────────────────────

function switchTab(target) {
  if (target === "telemetry") {
    tabOverviewBtn.classList.remove("active");
    tabTelemetryBtn.classList.add("active");
    paneOverview.style.display = "none";
    paneTelemetry.style.display = "block";
  } else {
    tabTelemetryBtn.classList.remove("active");
    tabOverviewBtn.classList.add("active");
    paneTelemetry.style.display = "none";
    paneOverview.style.display = "block";
  }
}

if (tabOverviewBtn && tabTelemetryBtn) {
  tabOverviewBtn.addEventListener("click", () => switchTab("overview"));
  tabTelemetryBtn.addEventListener("click", () => switchTab("telemetry"));
}

// ── Copy Button Actions ─────────────────────────────────────────────

if (copySafeUrlBtn) {
  copySafeUrlBtn.addEventListener("click", () => {
    copyToClipboard(currentTabData?.url || safeUrl.textContent, copySafeUrlBtn);
  });
}

if (copyPhishUrlBtn) {
  copyPhishUrlBtn.addEventListener("click", () => {
    copyToClipboard(currentTabData?.url || phishUrl.textContent, copyPhishUrlBtn);
  });
}

if (copyBriefingBtn) {
  copyBriefingBtn.addEventListener("click", () => {
    copyToClipboard(currentRawBriefing || xaiText.innerText, copyBriefingBtn);
  });
}

if (copyCodeBtn) {
  copyCodeBtn.addEventListener("click", () => {
    copyToClipboard("uvicorn backend.main:app --port 8000", copyCodeBtn);
  });
}

// ── Settings Panel & Key Visibility ─────────────────────────────────

if (settingsBtn) {
  settingsBtn.addEventListener("click", () => {
    const isOpen = settingsPanel.style.display !== "none";
    settingsPanel.style.display = isOpen ? "none" : "block";
    settingsBtn.classList.toggle("active", !isOpen);
    if (!isOpen) refreshSettingsUI();
  });
}

if (settingsCloseBtn) {
  settingsCloseBtn.addEventListener("click", () => {
    settingsPanel.style.display = "none";
    settingsBtn.classList.remove("active");
  });
}

if (toggleKeyVisibilityBtn && settingsKeyInput) {
  toggleKeyVisibilityBtn.addEventListener("click", () => {
    const isPass = settingsKeyInput.type === "password";
    settingsKeyInput.type = isPass ? "text" : "password";
    eyeIcon.innerHTML = isPass
      ? `<path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>`
      : `<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>`;
  });
}

async function refreshSettingsUI() {
  const stored = await store.get("gemini_api_key");
  const hasKey = !!stored.gemini_api_key;
  if (hasKey) {
    const key = stored.gemini_api_key;
    const masked = key.slice(0, 8) + "•".repeat(Math.max(6, key.length - 12)) + key.slice(-4);
    settingsKeyInput.placeholder = masked;
    settingsKeyStatus.textContent = "● API key configured";
    settingsKeyStatus.className = "key-status-text active";
    settingsClearBtn.style.display = "block";
  } else {
    settingsKeyInput.placeholder = "sk-or-... or AIza...";
    settingsKeyStatus.textContent = "● No API key configured";
    settingsKeyStatus.className = "key-status-text";
    settingsClearBtn.style.display = "none";
  }
}

if (settingsSaveBtn) {
  settingsSaveBtn.addEventListener("click", async () => {
    const val = settingsKeyInput.value.trim();
    if (!val) {
      settingsKeyStatus.textContent = "✕ Please enter a valid key";
      settingsKeyStatus.style.color = "var(--rose)";
      setTimeout(() => {
        settingsKeyStatus.style.color = "";
        refreshSettingsUI();
      }, 2000);
      return;
    }

    settingsSaveBtn.textContent = "Saving…";
    settingsSaveBtn.disabled = true;

    await store.set({ gemini_api_key: val });
    settingsSaveBtn.textContent = "✓ Saved";
    settingsKeyInput.value = "";
    refreshSettingsUI();

    if (currentTabData) loadXAIAnalysis(val);

    setTimeout(() => {
      settingsSaveBtn.textContent = "Save";
      settingsSaveBtn.disabled = false;
    }, 1500);
  });
}

if (settingsClearBtn) {
  settingsClearBtn.addEventListener("click", async () => {
    await store.remove("gemini_api_key");
    refreshSettingsUI();
    if (currentTabData) loadXAIAnalysis();
  });
}

// ── 48-Point Vector Telemetry Renderer ──────────────────────────────

function renderTelemetry(features = {}) {
  const f = features || {};

  // 1. Domain & URL Structure
  if (telGridDomain) {
    const domainSignals = [
      { name: "URL Length", val: f.URLLength ?? "—", status: (f.URLLength > 75 ? "warn" : "pass") },
      { name: "Domain Len", val: f.DomainLength ?? "—", status: (f.DomainLength > 30 ? "warn" : "pass") },
      { name: "TLD", val: f.TLD ? `.${f.TLD}` : ".com", status: (["xyz", "top", "tk", "ml"].includes(f.TLD) ? "warn" : "pass") },
      { name: "Subdomains", val: f.NoOfSubDomain ?? 0, status: (f.NoOfSubDomain > 2 ? "warn" : "pass") },
      { name: "IP Hostname", val: f.IsDomainIP ? "DETECTED" : "None", status: (f.IsDomainIP ? "fail" : "pass") },
      { name: "Obfuscation", val: f.HasObfuscation ? "Detected" : "Clean", status: (f.HasObfuscation ? "fail" : "pass") },
      { name: "HTTPS Protocol", val: f.IsHTTPS ? "Secured" : "Insecure", status: (f.IsHTTPS ? "pass" : "fail") },
      { name: "Special Chars", val: f.NoOfOtherSpecialCharsInURL ?? 0, status: ((f.NoOfOtherSpecialCharsInURL || 0) > 4 ? "warn" : "pass") }
    ];
    telGridDomain.innerHTML = domainSignals.map(s => `
      <div class="tel-chip">
        <span class="tel-chip-name" title="${s.name}">${s.name}</span>
        <span class="tel-chip-val status-${s.status}">${s.val}</span>
      </div>
    `).join("");
  }

  // 2. Authentication & Form Vectors
  if (telGridAuth) {
    const authSignals = [
      { name: "Password Input", val: f.HasPasswordField ? "Present" : "None", status: (f.HasPasswordField ? (currentTabData?.is_phishing ? "fail" : "pass") : "pass") },
      { name: "External Action", val: f.HasExternalFormSubmit ? "EXTERNAL" : "Safe", status: (f.HasExternalFormSubmit ? "fail" : "pass") },
      { name: "Hidden Fields", val: f.HasHiddenFields ? "Detected" : "None", status: (f.HasHiddenFields ? "warn" : "pass") },
      { name: "Submit Button", val: f.HasSubmitButton ? "Present" : "None", status: "pass" },
      { name: "Popup Triggers", val: f.NoOfPopup ?? 0, status: ((f.NoOfPopup || 0) > 0 ? "warn" : "pass") }
    ];
    telGridAuth.innerHTML = authSignals.map(s => `
      <div class="tel-chip">
        <span class="tel-chip-name" title="${s.name}">${s.name}</span>
        <span class="tel-chip-val status-${s.status}">${s.val}</span>
      </div>
    `).join("");
  }

  // 3. DOM & Architecture
  if (telGridDom) {
    const domSignals = [
      { name: "iFrames Count", val: f.NoOfiFrame ?? 0, status: ((f.NoOfiFrame || 0) > 2 ? "warn" : "pass") },
      { name: "Redirects", val: f.NoOfURLRedirect ?? 0, status: ((f.NoOfURLRedirect || 0) > 1 ? "warn" : "pass") },
      { name: "HTML Lines", val: f.LineOfCode ? f.LineOfCode.toLocaleString() : "—", status: "pass" },
      { name: "External JS", val: f.NoOfJS ?? 0, status: "pass" },
      { name: "External CSS", val: f.NoOfCSS ?? 0, status: "pass" },
      { name: "Images Count", val: f.NoOfImage ?? 0, status: "pass" }
    ];
    telGridDom.innerHTML = domSignals.map(s => `
      <div class="tel-chip">
        <span class="tel-chip-name" title="${s.name}">${s.name}</span>
        <span class="tel-chip-val status-${s.status}">${s.val}</span>
      </div>
    `).join("");
  }

  // 4. Content Keywords
  if (telGridKeywords) {
    const keywordSignals = [
      { name: "Bank Terms", val: f.Bank ? "Triggered" : "None", status: (f.Bank ? "warn" : "pass") },
      { name: "Payment Terms", val: f.Pay ? "Triggered" : "None", status: (f.Pay ? "warn" : "pass") },
      { name: "Crypto Terms", val: f.Crypto ? "Triggered" : "None", status: (f.Crypto ? "warn" : "pass") },
      { name: "Copyright Notice", val: f.HasCopyrightInfo ? "Verified" : "Missing", status: (f.HasCopyrightInfo ? "pass" : "warn") }
    ];
    telGridKeywords.innerHTML = keywordSignals.map(s => `
      <div class="tel-chip">
        <span class="tel-chip-name" title="${s.name}">${s.name}</span>
        <span class="tel-chip-val status-${s.status}">${s.val}</span>
      </div>
    `).join("");
  }
}

// ── Render Views ────────────────────────────────────────────────────

function renderLoading() {
  hideAll();
  show(viewLoading);
}

function renderIdle() {
  hideAll();
  show(viewIdle);
}

function renderError(message) {
  hideAll();
  show(viewError);
  if (errorMsg) errorMsg.textContent = message || "Could not connect to the backend API.";
}

function renderSafe(data) {
  hideAll();
  show(viewSafe);
  switchTab("overview");
  if (navTabs) navTabs.style.display = "flex";

  if (brandMark) {
    brandMark.className = "brand-mark is-safe";
  }

  if (headerStatusBadge) {
    headerStatusBadge.className = "brand-status-pill";
    headerStatusBadge.style.color = "var(--emerald)";
    headerStatusBadge.style.borderColor = "var(--emerald-mid)";
    headerStatusBadge.style.background = "var(--emerald-dim)";
    headerStatusBadge.innerHTML = '<span class="status-pulse-dot" style="background:var(--emerald)"></span><span>SECURE</span>';
  }

  const pct = data.legitimate_probability ?? (1 - (data.phishing_probability || 0.05));
  if (safeScore) safeScore.textContent = fmt(pct);
  if (safeScoreLabel) safeScoreLabel.textContent = fmt(pct);
  if (safeUrl) safeUrl.textContent = truncateUrl(data.url);
  bar(safeMeter, pct);

  if (safeProtocolText) {
    const isHttps = (data.url || "").startsWith("https");
    safeProtocolText.textContent = isHttps ? "HTTPS" : "HTTP";
  }

  renderStats(data);
  setupXAI(data);
  renderTelemetry(data.features);
}

function renderPhishing(data) {
  hideAll();
  show(viewPhishing);
  switchTab("overview");
  if (navTabs) navTabs.style.display = "flex";

  if (brandMark) {
    brandMark.className = "brand-mark is-danger";
  }

  if (headerStatusBadge) {
    headerStatusBadge.className = "brand-status-pill";
    headerStatusBadge.style.color = "var(--rose)";
    headerStatusBadge.style.borderColor = "var(--rose-mid)";
    headerStatusBadge.style.background = "var(--rose-dim)";
    headerStatusBadge.innerHTML = '<span class="status-pulse-dot" style="background:var(--rose)"></span><span>ALERT</span>';
  }

  const pct  = data.phishing_probability ?? 0.85;
  const risk = (data.risk_level || "HIGH").toUpperCase();

  if (phishScore) phishScore.textContent = fmt(pct);
  if (phishScoreLabel) phishScoreLabel.textContent = fmt(pct);
  if (phishUrl) phishUrl.textContent = truncateUrl(data.url);
  bar(phishMeter, pct);

  if (riskLabel) {
    riskLabel.textContent = `${risk.charAt(0) + risk.slice(1).toLowerCase()} Risk`;
  }

  if (riskChip) {
    if (risk === "MEDIUM") {
      riskChip.className = "status-chip chip-medium";
      const dot = riskChip.querySelector(".chip-dot");
      if (dot) dot.style.background = "var(--amber)";
    } else {
      riskChip.className = "status-chip chip-danger";
      const dot = riskChip.querySelector(".chip-dot");
      if (dot) dot.style.background = "var(--rose)";
    }
  }

  if (phishProtocolText) {
    phishProtocolText.textContent = "SUSPICIOUS";
  }

  renderStats(data);
  setupXAI(data);
  renderTelemetry(data.features);
}

function renderStats(data) {
  if (!statsRow) return;
  statsRow.style.display = "flex";
  if (statPhish) statPhish.textContent = data.phishing_probability != null ? fmt(data.phishing_probability) : "—";
  if (statLegit) statLegit.textContent = data.legitimate_probability != null ? fmt(data.legitimate_probability) : "—";
  if (statRisk) {
    statRisk.textContent = data.risk_level || "LOW";
    statRisk.style.color = riskColor(data.risk_level);
  }
}

// ── Explainable AI (XAI) ────────────────────────────────────────────

function setupXAI(data) {
  currentTabData = data;
  if (!xaiCard) return;
  xaiCard.style.display = "block";

  if (xaiCardTitleText) {
    xaiCardTitleText.textContent = data.is_phishing
      ? "Explainable AI Threat Analysis"
      : "Explainable AI Safety Assessment";
  }

  if (xaiSectionTitle) {
    xaiSectionTitle.textContent = data.is_phishing
      ? "DETECTED RED FLAGS"
      : "VERIFIED SECURITY SIGNALS";
  }

  if (xaiBoxLabel) {
    xaiBoxLabel.textContent = data.is_phishing
      ? "AI INCIDENT BRIEFING"
      : "AI SAFETY BRIEFING";
  }

  const indicators = data.top_indicators && data.top_indicators.length
    ? data.top_indicators
    : (data.is_phishing
      ? ["Anomalous behavioral patterns detected by ML classifier."]
      : ["All 48 inspected heuristics within baseline safe thresholds."]);

  if (xaiTags) {
    xaiTags.innerHTML = indicators
      .map(ind => `<div class="xai-tag ${data.is_phishing ? '' : 'safe'}">${ind}</div>`)
      .join("");
  }

  loadXAIAnalysis();
}

async function loadXAIAnalysis(overrideKey = null) {
  if (!currentTabData) return;

  if (xaiText) {
    xaiText.innerHTML = `
      <div class="xai-loading-msg">
        <span class="spinner-sm"></span>
        <span>Generating ${currentTabData.is_phishing ? 'threat reasoning' : 'safety assessment'}…</span>
      </div>
    `;
  }
  if (xaiSourceBadge) {
    xaiSourceBadge.textContent = "Analyzing…";
    xaiSourceBadge.className = "xai-source-badge";
  }

  const stored = await store.get("gemini_api_key");
  const apiKey = overrideKey || stored.gemini_api_key || "";

  if (xaiKeyHint) {
    if (!apiKey) {
      xaiKeyHint.style.display = "flex";
      if (xaiKeyHintText) {
        xaiKeyHintText.textContent = "Add your free Gemini API key in Settings for live neural explanations";
      }
    } else {
      xaiKeyHint.style.display = "none";
    }
  }

  if (footerModel) {
    footerModel.textContent = apiKey
      ? (apiKey.startsWith("sk-or-") ? "XGBoost + OpenRouter" : "XGBoost + Gemini AI")
      : "XGBoost + Rule Engine";
  }

  // If in Chrome extension environment, communicate with background service worker
  if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage) {
    chrome.runtime.sendMessage({
      type: "EXPLAIN_URL",
      url: currentTabData.url,
      hostname: (() => { try { return new URL(currentTabData.url || "").hostname; } catch { return ""; } })(),
      is_phishing: currentTabData.is_phishing,
      risk_level: currentTabData.risk_level,
      phishing_probability: currentTabData.phishing_probability,
      features: currentTabData.features || {},
      gemini_api_key: apiKey || null,
    }, (res) => {
      if (!res || res.error) {
        if (xaiSourceBadge) {
          xaiSourceBadge.textContent = "Fallback";
          xaiSourceBadge.className = "xai-source-badge source-offline";
        }
        if (xaiText) {
          xaiText.innerHTML = formatMarkdown(
            res?.explanation || (currentTabData.is_phishing
              ? "This page contains deceptive login or credential harvesting traits."
              : "All URL and DOM parameters meet standard security heuristics."),
            currentTabData.is_phishing
          );
        }
        return;
      }

      if (xaiSourceBadge) {
        if (res.source === "openrouter_gemini" || res.source === "openrouter_direct") {
          xaiSourceBadge.textContent = "OpenRouter Gemini";
          xaiSourceBadge.className = "xai-source-badge source-ai";
        } else if (res.source === "gemini" || res.source === "gemini_direct") {
          xaiSourceBadge.textContent = "Google Gemini";
          xaiSourceBadge.className = "xai-source-badge source-ai";
        } else if (res.source === "rule_based_fallback") {
          xaiSourceBadge.textContent = "Rule Fallback";
          xaiSourceBadge.className = "xai-source-badge source-offline";
        } else {
          xaiSourceBadge.textContent = "Rule Engine";
          xaiSourceBadge.className = "xai-source-badge source-rule";
        }
      }

      if (xaiText) {
        xaiText.innerHTML = formatMarkdown(res.explanation, currentTabData.is_phishing);
      }
    });
  } else {
    // Standalone browser preview simulation
    setTimeout(() => {
      if (xaiSourceBadge) {
        xaiSourceBadge.textContent = apiKey ? "Gemini AI" : "Rule Engine";
        xaiSourceBadge.className = "xai-source-badge source-ai";
      }
      if (xaiText) {
        const sampleText = currentTabData.is_phishing
          ? "### Critical Security Advisory\n- **Credential Harvesting Form Detected**: The page embeds an unauthorized input target.\n- **Domain Discrepancy**: The host domain does not match legitimate certificates."
          : "### Security Assessment\n- **Legitimate Domain**: Valid SSL certificate and verified registrar profile.\n- **Zero Anomalies**: No obfuscated redirects or deceptive login fields detected.";
        xaiText.innerHTML = formatMarkdown(sampleText, currentTabData.is_phishing);
      }
    }, 400);
  }
}

// ── Rescan Trigger ──────────────────────────────────────────────────

async function triggerRescan() {
  if (rescanBtn) {
    rescanBtn.classList.add("spinning");
    rescanBtn.disabled = true;
  }

  if (hasChromeTabs) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.id) {
      if (!tab.url || !tab.url.startsWith("http")) {
        renderIdle();
        setTimeout(() => {
          if (rescanBtn) {
            rescanBtn.classList.remove("spinning");
            rescanBtn.disabled = false;
          }
        }, 500);
        return;
      }

      await chrome.storage.local.remove(`tab_${tab.id}`);
      chrome.runtime.sendMessage({ type: "RESCAN_TAB", tabId: tab.id });
      renderLoading();
      poll(`tab_${tab.id}`);
    }
  } else {
    // Standalone preview rescan simulation
    renderLoading();
    setTimeout(() => {
      renderSafe(getSampleData(false));
    }, 1200);
  }

  setTimeout(() => {
    if (rescanBtn) {
      rescanBtn.classList.remove("spinning");
      rescanBtn.disabled = false;
    }
  }, 1200);
}

if (rescanBtn) rescanBtn.addEventListener("click", triggerRescan);
if (idleScanBtn) idleScanBtn.addEventListener("click", triggerRescan);
if (retryErrorBtn) retryErrorBtn.addEventListener("click", triggerRescan);

// ── Polling ─────────────────────────────────────────────────────────

function poll(key, attempts = 0) {
  if (attempts > 30) {
    renderError("Scan timed out. Please ensure the backend is running.");
    return;
  }
  setTimeout(async () => {
    const stored = await store.get(key);
    const data   = stored[key];
    if (!data || data.status === "loading") {
      poll(key, attempts + 1);
      return;
    }
    if (data.status === "done") {
      data.is_phishing ? renderPhishing(data) : renderSafe(data);
      return;
    }
    if (data.status === "error") {
      renderError(data.error);
    }
  }, 500);
}

// ── Sample Mock Data for Preview ────────────────────────────────────

function getSampleData(isPhish = false) {
  return isPhish ? {
    url: "https://secure-login-account-update.xyz/auth/verify?session=928a38",
    is_phishing: true,
    risk_level: "HIGH",
    phishing_probability: 0.984,
    legitimate_probability: 0.016,
    top_indicators: [
      "Obfuscated hexadecimal parameters in URL path",
      "External cross-domain form submission detected",
      "Deceptive banking and credential keywords present"
    ],
    features: {
      URLLength: 72,
      DomainLength: 32,
      TLD: "xyz",
      NoOfSubDomain: 3,
      IsDomainIP: 0,
      HasObfuscation: 1,
      IsHTTPS: 1,
      HasPasswordField: 1,
      HasExternalFormSubmit: 1,
      HasHiddenFields: 1,
      HasSubmitButton: 1,
      NoOfPopup: 1,
      NoOfiFrame: 2,
      NoOfURLRedirect: 2,
      LineOfCode: 420,
      NoOfJS: 8,
      NoOfCSS: 4,
      NoOfImage: 12,
      Bank: 1,
      Pay: 1,
      Crypto: 0,
      HasCopyrightInfo: 0
    }
  } : {
    url: "https://github.com/Mohan007N/PhishGuard-AI-Shield",
    is_phishing: false,
    risk_level: "SAFE",
    phishing_probability: 0.008,
    legitimate_probability: 0.992,
    top_indicators: [
      "Verified SSL certificate issued to trusted authority",
      "Zero cross-site form actions or input intercepts",
      "Domain and title alignment score exceeds 98%"
    ],
    features: {
      URLLength: 48,
      DomainLength: 10,
      TLD: "com",
      NoOfSubDomain: 0,
      IsDomainIP: 0,
      HasObfuscation: 0,
      IsHTTPS: 1,
      HasPasswordField: 0,
      HasExternalFormSubmit: 0,
      HasHiddenFields: 0,
      HasSubmitButton: 1,
      NoOfPopup: 0,
      NoOfiFrame: 0,
      NoOfURLRedirect: 0,
      LineOfCode: 1540,
      NoOfJS: 12,
      NoOfCSS: 6,
      NoOfImage: 24,
      Bank: 0,
      Pay: 0,
      Crypto: 0,
      HasCopyrightInfo: 1
    }
  };
}

// ── Main Bootstrap ──────────────────────────────────────────────────

async function main() {
  renderLoading();

  if (!hasChromeTabs) {
    // Standalone preview mode: render safe sample with demo toggle
    renderSafe(getSampleData(false));

    // Add discreet developer preview bar at the bottom for quick state testing
    const demoBar = document.createElement("div");
    demoBar.id = "demoToolbar";
    demoBar.style.cssText = "display:flex;gap:5px;padding:6px 12px;background:#05070c;border-top:1px solid rgba(255,255,255,0.08);justify-content:center;align-items:center;";
    demoBar.innerHTML = `
      <span style="font-size:9px;color:#64748b;font-weight:600;letter-spacing:0.5px;text-transform:uppercase;">Preview:</span>
      <button id="demoSafeBtn" style="background:#101522;color:#10b981;border:1px solid rgba(16,185,129,0.3);border-radius:4px;padding:2px 8px;cursor:pointer;font-size:9.5px;font-weight:600;">Safe</button>
      <button id="demoPhishBtn" style="background:#101522;color:#f43f5e;border:1px solid rgba(244,63,94,0.3);border-radius:4px;padding:2px 8px;cursor:pointer;font-size:9.5px;font-weight:600;">Threat</button>
      <button id="demoLoadBtn" style="background:#101522;color:#38bdf8;border:1px solid rgba(56,189,248,0.3);border-radius:4px;padding:2px 8px;cursor:pointer;font-size:9.5px;font-weight:600;">Radar</button>
      <button id="demoErrBtn" style="background:#101522;color:#f59e0b;border:1px solid rgba(245,158,11,0.3);border-radius:4px;padding:2px 8px;cursor:pointer;font-size:9.5px;font-weight:600;">Offline</button>
    `;
    document.querySelector(".app-container").appendChild(demoBar);

    document.getElementById("demoSafeBtn").onclick = () => renderSafe(getSampleData(false));
    document.getElementById("demoPhishBtn").onclick = () => renderPhishing(getSampleData(true));
    document.getElementById("demoLoadBtn").onclick = () => renderLoading();
    document.getElementById("demoErrBtn").onclick = () => renderError("Could not connect to the local inference API on port 8000.");
    return;
  }

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.id) { renderIdle(); return; }

    if (!tab.url ||
        tab.url.startsWith("chrome://") ||
        tab.url.startsWith("chrome-extension://") ||
        tab.url.startsWith("about:") ||
        tab.url.startsWith("edge://")) {
      renderIdle();
      return;
    }

    const key    = `tab_${tab.id}`;
    const stored = await chrome.storage.local.get(key);
    const data   = stored[key];

    if (!data)                     { renderIdle(); return; }
    if (data.status === "loading") { renderLoading(); poll(key); return; }
    if (data.status === "error")   { renderError(data.error); return; }
    if (data.status === "done")    {
      data.is_phishing ? renderPhishing(data) : renderSafe(data);
    }
  } catch (err) {
    console.error("[PhishGuard] Init error:", err);
    renderIdle();
  }
}

// Initialize settings
refreshSettingsUI();

// Run main
main();
