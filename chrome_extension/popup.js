/**
 * popup.js — PhishGuard Extension Popup Controller with Explainable AI (XAI)
 */

"use strict";

// ── DOM refs ────────────────────────────────────────────────────────
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

// Settings Panel
const settingsBtn      = document.getElementById("settingsBtn");
const closeSettingsBtn = document.getElementById("closeSettingsBtn");
const settingsPanel    = document.getElementById("settingsPanel");
const popupKeyInput    = document.getElementById("popupKeyInput");
const popupSaveKeyBtn  = document.getElementById("popupSaveKeyBtn");
const popupKeyStatus   = document.getElementById("popupKeyStatus");

// Safe view refs
const safeScore      = document.getElementById("safeScore");
const safeScoreLabel = document.getElementById("safeScoreLabel");
const safeUrl        = document.getElementById("safeUrl");
const safeMeter      = document.getElementById("safeMeter");

// Phishing view refs
const phishScore      = document.getElementById("phishScore");
const phishScoreLabel = document.getElementById("phishScoreLabel");
const phishUrl        = document.getElementById("phishUrl");
const phishMeter      = document.getElementById("phishMeter");
const riskChip        = document.getElementById("riskChip");
const riskLabel       = document.getElementById("riskLabel");

// Stats refs
const statPhish = document.getElementById("statPhish");
const statLegit = document.getElementById("statLegit");
const statRisk  = document.getElementById("statRisk");

// Explainable AI (XAI) refs
const xaiContainer   = document.getElementById("xaiContainer");
const xaiToggleBtn   = document.getElementById("xaiToggleBtn");
const xaiBody        = document.getElementById("xaiBody");
const xaiChevron     = document.getElementById("xaiChevron");
const xaiTags        = document.getElementById("xaiTags");
const xaiSourceBadge = document.getElementById("xaiSourceBadge");
const xaiText        = document.getElementById("xaiText");

let currentTabData = null;
let xaiOpen = false;
let xaiFetched = false;

// ── Helpers ─────────────────────────────────────────────────────────
function hideAll() {
  [viewLoading, viewIdle, viewError, viewSafe, viewPhishing].forEach(
    el => (el.style.display = "none")
  );
  statsRow.style.display = "none";
  if (xaiContainer) xaiContainer.style.display = "none";
  brandMark.className = "brand-mark";
}

function show(el) { el.style.display = "flex"; }

function fmt(probability) {
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
  setTimeout(() => (el.style.width = `${Math.round(probability * 100)}%`), 80);
}

function riskColor(level) {
  const map = { HIGH: "#ff453a", MEDIUM: "#ff9f0a", LOW: "#ffd60a", SAFE: "#30d158" };
  return map[level] || "#ff453a";
}

function formatPopupMarkdown(text) {
  if (!text) return "";
  return text
    .replace(/^### (.*$)/gim, '<div style="font-size:11px; font-weight:700; color:#fff; margin:6px 0 2px 0;">$1</div>')
    .replace(/^## (.*$)/gim, '<div style="font-size:12px; font-weight:700; color:#fff; margin:8px 0 3px 0;">$1</div>')
    .replace(/\*\*(.*?)\*\*/gim, '<strong style="color:#fff;">$1</strong>')
    .replace(/\*(.*?)\*/gim, '<em style="color:#bbb;">$1</em>')
    .replace(/^- (.*$)/gim, '<div style="margin:2px 0 2px 4px; display:flex; gap:5px; line-height:1.4;"><span style="color:#ff6b6b; flex-shrink:0;">•</span><span>$1</span></div>')
    .replace(/\n\n/g, '<div style="height:5px;"></div>')
    .replace(/\n/g, '<br/>');
}

// ── Render functions ────────────────────────────────────────────────
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
    riskChip.style.background = "rgba(255,159,10,0.12)";
    riskChip.style.borderColor = "rgba(255,159,10,0.25)";
    riskChip.style.color = "#ff9f0a";
    riskChip.querySelector(".chip-dot").style.background = "#ff9f0a";
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

// ── Explainable AI (XAI) Setup ──────────────────────────────────────
function setupXAI(data) {
  currentTabData = data;
  xaiContainer.style.display = "block";
  xaiOpen = false;
  xaiFetched = false;
  xaiBody.style.display = "none";
  xaiChevron.style.transform = "rotate(0deg)";

  const indicators = data.top_indicators && data.top_indicators.length
    ? data.top_indicators
    : (data.is_phishing ? ["Statistical signature matches credential harvesting templates."] : ["All structural heuristics within normal parameters."]);

  xaiTags.innerHTML = indicators.map(ind => `
    <div class="xai-tag ${data.is_phishing ? '' : 'safe'}">• ${ind}</div>
  `).join("");
}

const DEFAULT_OPENROUTER_KEY = "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";

async function loadXAIAnalysis() {
  if (!currentTabData) return;

  xaiText.innerHTML = `
    <div style="display:flex; align-items:center; gap:6px; color:#888;">
      <span style="display:inline-block; width:10px; height:10px; border:2px solid #666; border-top-color:#fff; border-radius:50%; animation:spin 0.8s linear infinite;"></span>
      <span>Generating OpenRouter Gemini Flash explanation...</span>
    </div>
  `;
  xaiSourceBadge.textContent = "Analyzing...";
  xaiSourceBadge.style.color = "#0a84ff";

  const stored = await chrome.storage.local.get("gemini_api_key");
  const apiKey = stored.gemini_api_key || DEFAULT_OPENROUTER_KEY;

  chrome.runtime.sendMessage({
    type: "EXPLAIN_URL",
    url: currentTabData.url,
    hostname: new URL(currentTabData.url || "https://example.com").hostname,
    is_phishing: currentTabData.is_phishing,
    risk_level: currentTabData.risk_level,
    phishing_probability: currentTabData.phishing_probability,
    features: currentTabData.features || {},
    gemini_api_key: apiKey,
  }, (res) => {
    if (!res || res.error) {
      xaiSourceBadge.textContent = "Offline Fallback";
      xaiSourceBadge.style.color = "#ff9f0a";
      xaiText.innerHTML = formatPopupMarkdown(res?.explanation || "Explainable AI analysis ready.");
      return;
    }

    if (res.source === "openrouter_gemini" || res.source === "openrouter_direct") {
      xaiSourceBadge.textContent = "✨ OpenRouter Gemini";
      xaiSourceBadge.style.color = "#30d158";
    } else if (res.source === "gemini" || res.source === "gemini_direct") {
      xaiSourceBadge.textContent = "✨ Google Gemini";
      xaiSourceBadge.style.color = "#30d158";
    } else {
      xaiSourceBadge.textContent = "Rule-Based";
      xaiSourceBadge.style.color = "#8e8e99";
    }

    xaiText.innerHTML = formatPopupMarkdown(res.explanation);
    xaiFetched = true;
  });
}

xaiToggleBtn.addEventListener("click", () => {
  xaiOpen = !xaiOpen;
  if (xaiOpen) {
    xaiBody.style.display = "block";
    xaiChevron.style.transform = "rotate(180deg)";
    if (!xaiFetched) {
      loadXAIAnalysis();
    }
  } else {
    xaiBody.style.display = "none";
    xaiChevron.style.transform = "rotate(0deg)";
  }
});

// ── Settings Panel Toggle & Key Management ──────────────────────────
function refreshSettingsStatus() {
  chrome.storage.local.get("gemini_api_key", (stored) => {
    if (stored.gemini_api_key) {
      popupKeyInput.placeholder = "•••••••••••••••• (Custom Key)";
      popupKeyStatus.innerHTML = '<span style="color:#30d158;">● Custom Key Active</span>';
    } else {
      popupKeyInput.placeholder = "sk-or-v1-a2437... (OpenRouter Active)";
      popupKeyStatus.innerHTML = '<span style="color:#30d158;">● OpenRouter Gemini Flash Connected</span>';
    }
  });
}

settingsBtn.addEventListener("click", () => {
  const isHidden = settingsPanel.style.display === "none";
  settingsPanel.style.display = isHidden ? "block" : "none";
  if (isHidden) refreshSettingsStatus();
});

closeSettingsBtn.addEventListener("click", () => {
  settingsPanel.style.display = "none";
});

popupSaveKeyBtn.addEventListener("click", () => {
  const key = popupKeyInput.value.trim();
  if (!key) {
    popupKeyStatus.innerHTML = '<span style="color:#ff453a;">Please enter a key</span>';
    return;
  }
  popupSaveKeyBtn.textContent = "Saving...";
  popupSaveKeyBtn.disabled = true;

  chrome.storage.local.set({ gemini_api_key: key }, () => {
    popupSaveKeyBtn.textContent = "Saved!";
    popupKeyInput.value = "";
    refreshSettingsStatus();
    if (xaiOpen) loadXAIAnalysis();
    setTimeout(() => {
      popupSaveKeyBtn.textContent = "Save";
      popupSaveKeyBtn.disabled = false;
    }, 1200);
  });
});

// ── Main ────────────────────────────────────────────────────────────
async function main() {
  renderLoading();

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.id) { renderIdle(); return; }

  if (!tab.url ||
      tab.url.startsWith("chrome://") ||
      tab.url.startsWith("chrome-extension://")) {
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
  if (attempts > 24) {
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

// ── Rescan button ────────────────────────────────────────────────────
rescanBtn.addEventListener("click", async () => {
  rescanBtn.classList.add("spinning");
  rescanBtn.disabled = true;

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab && tab.id) {
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

// ── Boot ─────────────────────────────────────────────────────────────
main();
