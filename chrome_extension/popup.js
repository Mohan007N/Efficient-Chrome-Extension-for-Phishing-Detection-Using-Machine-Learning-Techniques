/**
 * popup.js — PhishGuard Extension Popup Controller
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

// Safe
const safeScore      = document.getElementById("safeScore");
const safeScoreLabel = document.getElementById("safeScoreLabel");
const safeUrl        = document.getElementById("safeUrl");
const safeMeter      = document.getElementById("safeMeter");

// Phishing
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

// ── Helpers ─────────────────────────────────────────────────────────
function hideAll() {
  [viewLoading, viewIdle, viewError, viewSafe, viewPhishing].forEach(
    el => (el.style.display = "none")
  );
  statsRow.style.display = "none";
  brandMark.className = "brand-mark";
}

function show(el) { el.style.display = "flex"; }

function fmt(probability) {
  return `${(probability * 100).toFixed(1)}%`;
}

function truncateUrl(url, max = 36) {
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
  const map = { HIGH: "#ff453a", MEDIUM: "#ff9f0a", LOW: "#ffd60a" };
  return map[level] || "#ff453a";
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

  // Update chip color for medium / low
  if (risk === "MEDIUM") {
    riskChip.style.background = "rgba(255,159,10,0.12)";
    riskChip.style.borderColor = "rgba(255,159,10,0.25)";
    riskChip.style.color = "#ff9f0a";
    riskChip.querySelector(".chip-dot").style.background = "#ff9f0a";
  }

  renderStats(data);
}

function renderStats(data) {
  statsRow.style.display = "flex";
  statPhish.textContent = data.phishing_probability != null ? fmt(data.phishing_probability) : "—";
  statLegit.textContent = data.legitimate_probability != null ? fmt(data.legitimate_probability) : "—";
  statRisk.textContent  = data.risk_level || "—";
  statRisk.style.color  = riskColor(data.risk_level);
}

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

  if (!data)                 { renderIdle(); return; }
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
