/**
 * popup.js — PhishGuard Extension Popup Controller
 *
 * Clean, professional UI controller with:
 * - No hardcoded API keys — user provides their own via Settings
 * - Explainable AI (XAI) analysis powered by user's API key
 * - Rule-based fallback when no key is configured
 */

"use strict";

// ── DOM References ──────────────────────────────────────────────────
const viewLoading  = document.getElementById("viewLoading");
const viewIdle     = document.getElementById("viewIdle");
const viewError    = document.getElementById("viewError");
const viewSafe     = document.getElementById("viewSafe");
const viewPhishing = document.getElementById("viewPhishing");

const brandMark    = document.getElementById("brandMark");
const rescanBtn    = document.getElementById("rescanBtn");
const rescanIcon   = document.getElementById("rescanIcon");
const statsRow     = document.getElementById("statsRow");
const errorMsg     = document.getElementById("errorMsg");

// Safe view
const safeScore      = document.getElementById("safeScore");
const safeScoreLabel = document.getElementById("safeScoreLabel");
const safeUrl        = document.getElementById("safeUrl");
const safeMeter      = document.getElementById("safeMeter");

// Phishing view
const phishScore      = document.getElementById("phishScore");
const phishScoreLabel = document.getElementById("phishScoreLabel");
const phishUrl        = document.getElementById("phishUrl");
const phishMeter      = document.getElementById("phishMeter");
const riskChip        = document.getElementById("riskChip");
const riskLabel       = document.getElementById("riskLabel");

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
const footerModel      = document.getElementById("footerModel");

// Settings panel
const settingsBtn      = document.getElementById("settingsBtn");
const settingsPanel    = document.getElementById("settingsPanel");
const settingsCloseBtn = document.getElementById("settingsCloseBtn");
const settingsKeyInput = document.getElementById("settingsKeyInput");
const settingsSaveBtn  = document.getElementById("settingsSaveBtn");
const settingsKeyStatus = document.getElementById("settingsKeyStatus");
const settingsClearBtn = document.getElementById("settingsClearBtn");

let currentTabData = null;

// ── Helpers ─────────────────────────────────────────────────────────

function hideAll() {
  [viewLoading, viewIdle, viewError, viewSafe, viewPhishing].forEach(
    el => (el.style.display = "none")
  );
  statsRow.style.display = "none";
  if (xaiCard) xaiCard.style.display = "none";
  brandMark.className = "brand-mark";
}

function show(el) { el.style.display = "flex"; }

function fmt(probability) {
  return `${(probability * 100).toFixed(1)}%`;
}

function truncateUrl(url, max = 38) {
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
  setTimeout(() => (el.style.width = `${Math.round(probability * 100)}%`), 80);
}

function riskColor(level) {
  const map = { HIGH: "#fb7185", MEDIUM: "#fbbf24", LOW: "#fbbf24", SAFE: "#34d399" };
  return map[level] || "#fb7185";
}

/**
 * Converts simple markdown to styled HTML for the XAI briefing.
 */
function formatMarkdown(text, isPhishing) {
  if (!text) return "";
  const dotClass = isPhishing ? "" : " safe-dot";
  return text
    .replace(/^### (.*$)/gim, '<div class="md-heading">$1</div>')
    .replace(/^## (.*$)/gim, '<div class="md-heading">$1</div>')
    .replace(/\*\*(.*?)\*\*/gim, "<strong>$1</strong>")
    .replace(/^[\*\-] +([^\n\r]+)/gim,
      `<div class="md-bullet"><span class="md-bullet-dot${dotClass}">▸</span><span>$1</span></div>`)
    .replace(/\*([^\*]+)\*/gim, "<em>$1</em>")
    .replace(/\n\n/g, '<div style="height:5px;"></div>')
    .replace(/\n/g, "<br/>");
}

// ── Settings Panel ──────────────────────────────────────────────────

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

function refreshSettingsUI() {
  chrome.storage.local.get("gemini_api_key", (stored) => {
    const hasKey = !!stored.gemini_api_key;
    if (hasKey) {
      const key = stored.gemini_api_key;
      const masked = key.slice(0, 8) + "•".repeat(12) + key.slice(-4);
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
  });
}

if (settingsSaveBtn) {
  settingsSaveBtn.addEventListener("click", () => {
    const val = settingsKeyInput.value.trim();
    if (!val) {
      settingsKeyStatus.textContent = "✕ Please enter a valid key";
      settingsKeyStatus.className = "key-status-text";
      settingsKeyStatus.style.color = "#fb7185";
      setTimeout(() => {
        settingsKeyStatus.style.color = "";
        refreshSettingsUI();
      }, 2000);
      return;
    }

    settingsSaveBtn.textContent = "Saving…";
    settingsSaveBtn.disabled = true;

    chrome.storage.local.set({ gemini_api_key: val }, () => {
      settingsSaveBtn.textContent = "✓ Saved";
      settingsKeyInput.value = "";
      refreshSettingsUI();

      // Re-trigger XAI if we have data
      if (currentTabData) loadXAIAnalysis(val);

      setTimeout(() => {
        settingsSaveBtn.textContent = "Save";
        settingsSaveBtn.disabled = false;
      }, 1500);
    });
  });
}

if (settingsClearBtn) {
  settingsClearBtn.addEventListener("click", () => {
    chrome.storage.local.remove("gemini_api_key", () => {
      refreshSettingsUI();
      if (currentTabData) loadXAIAnalysis();
    });
  });
}

// ── Render Functions ────────────────────────────────────────────────

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
  errorMsg.textContent = message || "Could not reach the backend API.";
}

function renderSafe(data) {
  hideAll();
  show(viewSafe);
  brandMark.classList.add("is-safe");

  const pct = data.legitimate_probability ?? (1 - data.phishing_probability);
  safeScore.textContent  = fmt(pct);
  safeScoreLabel.textContent = fmt(pct);
  safeUrl.textContent    = truncateUrl(data.url);
  bar(safeMeter, pct);

  renderStats(data);
  setupXAI(data);
}

function renderPhishing(data) {
  hideAll();
  show(viewPhishing);
  brandMark.classList.add("is-danger");

  const pct  = data.phishing_probability ?? 0.5;
  const risk = (data.risk_level || "HIGH").toUpperCase();

  phishScore.textContent      = fmt(pct);
  phishScoreLabel.textContent = fmt(pct);
  phishUrl.textContent        = truncateUrl(data.url);
  bar(phishMeter, pct);

  riskLabel.textContent = `${risk.charAt(0) + risk.slice(1).toLowerCase()} Risk`;

  if (risk === "MEDIUM") {
    riskChip.className = "status-chip chip-medium";
    riskChip.querySelector(".chip-dot").style.background = "var(--amber)";
  }

  renderStats(data);
  setupXAI(data);
}

function renderStats(data) {
  statsRow.style.display = "flex";
  statPhish.textContent = data.phishing_probability != null ? fmt(data.phishing_probability) : "—";
  statLegit.textContent = data.legitimate_probability != null ? fmt(data.legitimate_probability) : "—";
  statRisk.textContent  = data.risk_level || "—";
  statRisk.style.color  = riskColor(data.risk_level);
}

// ── Explainable AI (XAI) ────────────────────────────────────────────

function setupXAI(data) {
  currentTabData = data;
  if (!xaiCard) return;
  xaiCard.style.display = "block";

  // Title
  if (xaiCardTitleText) {
    xaiCardTitleText.textContent = data.is_phishing
      ? "Explainable AI Threat Analysis"
      : "Explainable AI Safety Assessment";
  }

  // Section title
  if (xaiSectionTitle) {
    xaiSectionTitle.textContent = data.is_phishing
      ? "DETECTED RED FLAGS"
      : "VERIFIED SECURITY SIGNALS";
  }

  // Box label
  if (xaiBoxLabel) {
    xaiBoxLabel.textContent = data.is_phishing
      ? "AI INCIDENT BRIEFING"
      : "AI SAFETY BRIEFING";
  }

  // Indicators
  const indicators = data.top_indicators && data.top_indicators.length
    ? data.top_indicators
    : (data.is_phishing
      ? ["Anomalous patterns detected by ML classifier."]
      : ["All heuristics within normal parameters."]);

  xaiTags.innerHTML = indicators
    .map(ind => `<div class="xai-tag ${data.is_phishing ? '' : 'safe'}">${ind}</div>`)
    .join("");

  loadXAIAnalysis();
}

async function loadXAIAnalysis(overrideKey = null) {
  if (!currentTabData) return;

  // Show loading state
  xaiText.innerHTML = `
    <div class="xai-loading-msg">
      <span class="spinner-sm"></span>
      <span>Generating ${currentTabData.is_phishing ? 'threat' : 'safety'} analysis…</span>
    </div>
  `;
  xaiSourceBadge.textContent = "Analyzing…";
  xaiSourceBadge.className = "xai-source-badge";

  // Get API key from storage (user-provided only)
  const stored = await chrome.storage.local.get("gemini_api_key");
  const apiKey = overrideKey || stored.gemini_api_key || "";

  // Show hint if no key
  if (xaiKeyHint) {
    if (!apiKey) {
      xaiKeyHint.style.display = "flex";
      xaiKeyHintText.textContent = "Add an API key in ⚙ Settings for AI-powered explanations";
    } else {
      xaiKeyHint.style.display = "none";
    }
  }

  // Update footer
  if (footerModel) {
    footerModel.textContent = apiKey
      ? (apiKey.startsWith("sk-or-") ? "XGBoost + OpenRouter" : "XGBoost + Gemini")
      : "XGBoost + Rule Engine";
  }

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
      xaiSourceBadge.textContent = "Fallback";
      xaiSourceBadge.className = "xai-source-badge source-offline";
      xaiText.innerHTML = formatMarkdown(
        res?.explanation || "Rule-based analysis completed.",
        currentTabData.is_phishing
      );
      return;
    }

    // Set source badge
    if (res.source === "openrouter_gemini" || res.source === "openrouter_direct") {
      xaiSourceBadge.textContent = "OpenRouter Gemini";
      xaiSourceBadge.className = "xai-source-badge source-ai";
    } else if (res.source === "gemini" || res.source === "gemini_direct") {
      xaiSourceBadge.textContent = "Google Gemini";
      xaiSourceBadge.className = "xai-source-badge source-ai";
    } else if (res.source === "rule_based_fallback") {
      xaiSourceBadge.textContent = "Rule-Based Fallback";
      xaiSourceBadge.className = "xai-source-badge source-offline";
    } else {
      xaiSourceBadge.textContent = "Rule Engine";
      xaiSourceBadge.className = "xai-source-badge source-rule";
    }

    xaiText.innerHTML = formatMarkdown(res.explanation, currentTabData.is_phishing);
  });
}

// ── Main ────────────────────────────────────────────────────────────

async function main() {
  renderLoading();

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.id) { renderIdle(); return; }

  if (!tab.url ||
      tab.url.startsWith("chrome://") ||
      tab.url.startsWith("chrome-extension://") ||
      tab.url.startsWith("about:")) {
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
}

// ── Polling ─────────────────────────────────────────────────────────

function poll(key, attempts = 0) {
  if (attempts > 30) {
    renderError("Scan timed out. Is the API server running?");
    return;
  }
  setTimeout(async () => {
    const stored = await chrome.storage.local.get(key);
    const data   = stored[key];
    if (!data || data.status === "loading") { poll(key, attempts + 1); return; }
    if (data.status === "done")  { data.is_phishing ? renderPhishing(data) : renderSafe(data); return; }
    if (data.status === "error") { renderError(data.error); }
  }, 500);
}

// ── Rescan Button ───────────────────────────────────────────────────

rescanBtn.addEventListener("click", async () => {
  rescanBtn.classList.add("spinning");
  rescanBtn.disabled = true;

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab && tab.id) {
    if (!tab.url || !tab.url.startsWith("http")) {
      renderIdle();
      setTimeout(() => {
        rescanBtn.classList.remove("spinning");
        rescanBtn.disabled = false;
      }, 500);
      return;
    }

    await chrome.storage.local.remove(`tab_${tab.id}`);
    chrome.runtime.sendMessage({ type: "RESCAN_TAB", tabId: tab.id });
    renderLoading();
    poll(`tab_${tab.id}`);
  }

  setTimeout(() => {
    rescanBtn.classList.remove("spinning");
    rescanBtn.disabled = false;
  }, 1200);
});

// ── Initialize Settings UI on load ──────────────────────────────────
refreshSettingsUI();

// ── Boot ─────────────────────────────────────────────────────────────
main();
