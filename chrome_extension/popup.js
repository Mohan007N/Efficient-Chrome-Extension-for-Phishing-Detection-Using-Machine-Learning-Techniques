/**
 * popup.js — WebShield AI Popup Dashboard Controller (Manifest V3)
 *
 * Displays separated multi-dimension website safety assessment, local scan history,
 * dark/light theme persistence, configurable API URL, user-confirmed trust list,
 * and feedback reporting (/feedback). Never fabricates risk scores or history.
 */

"use strict";

const DEFAULT_API_BASE = "http://127.0.0.1:8000";

const $ = (id) => document.getElementById(id);

const hasChromeStorage = typeof chrome !== "undefined" && chrome.storage && chrome.storage.local;
const hasChromeTabs = typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.query;
const hasChromeRuntime = typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage;

const store = {
  get: (key) => new Promise((resolve) => {
    if (hasChromeStorage) chrome.storage.local.get(key, resolve);
    else {
      try { resolve({ [key]: JSON.parse(localStorage.getItem(key) || "null") ?? undefined }); }
      catch { resolve({}); }
    }
  }),
  set: (obj) => new Promise((resolve) => {
    if (hasChromeStorage) chrome.storage.local.set(obj, resolve);
    else {
      Object.entries(obj).forEach(([k, v]) => localStorage.setItem(k, JSON.stringify(v)));
      resolve();
    }
  }),
  remove: (key) => new Promise((resolve) => {
    if (hasChromeStorage) chrome.storage.local.remove(key, resolve);
    else { localStorage.removeItem(key); resolve(); }
  }),
};

let currentData = null;

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme === "light" ? "light" : "dark");
}

async function initTheme() {
  const res = await store.get("ui_theme");
  applyTheme(res.ui_theme || "dark");
}

$("themeToggleBtn")?.addEventListener("click", async () => {
  const curr = document.documentElement.getAttribute("data-theme") || "dark";
  const next = curr === "dark" ? "light" : "dark";
  applyTheme(next);
  await store.set({ ui_theme: next });
});

// Tabs
function switchTab(name) {
  ["Overview", "Signals", "History"].forEach((t) => {
    const low = t.toLowerCase();
    const btn = $(`tab${t}Btn`);
    const pane = $(`pane${t}`);
    if (btn) btn.classList.toggle("active", low === name);
    if (pane) pane.style.display = low === name ? "block" : "none";
  });
  if (name === "history") renderHistory();
}

$("tabOverviewBtn")?.addEventListener("click", () => switchTab("overview"));
$("tabSignalsBtn")?.addEventListener("click", () => switchTab("signals"));
$("tabHistoryBtn")?.addEventListener("click", () => switchTab("history"));

// Settings Drawer
$("settingsBtn")?.addEventListener("click", async () => {
  const panel = $("settingsPanel");
  const open = panel.style.display !== "none";
  panel.style.display = open ? "none" : "block";
  if (!open) await refreshSettings();
});
$("settingsCloseBtn")?.addEventListener("click", () => { $("settingsPanel").style.display = "none"; });

async function refreshSettings() {
  const data = await store.get(["api_base_url", "trusted_domains"]);
  $("apiBaseInput").value = data.api_base_url || DEFAULT_API_BASE;
  const trusted = Array.isArray(data.trusted_domains) ? data.trusted_domains : [];
  $("trustedCount").textContent = String(trusted.length);
  $("trustedDomainsList").innerHTML = trusted.length
    ? trusted.map(d => `<span class="trusted-chip">${d}</span>`).join("")
    : `<span class="brand-sub">None added.</span>`;
}

$("saveApiBtn")?.addEventListener("click", async () => {
  const val = ($("apiBaseInput").value || "").trim().replace(/\/+$/, "");
  if (!/^https?:\/\/.+/.test(val)) {
    $("apiSaveStatus").textContent = "Enter a valid http:// or https:// URL.";
    return;
  }
  await store.set({ api_base_url: val });
  $("apiSaveStatus").textContent = "Saved.";
  checkBackendHealth();
});

$("resetApiBtn")?.addEventListener("click", async () => {
  await store.remove("api_base_url");
  $("apiBaseInput").value = DEFAULT_API_BASE;
  $("apiSaveStatus").textContent = "Reset to localhost.";
  checkBackendHealth();
});

$("clearTrustedBtn")?.addEventListener("click", async () => {
  await store.set({ trusted_domains: [] });
  await refreshSettings();
});

// Backend health indicator
function checkBackendHealth() {
  const pill = $("backendStatusPill");
  if (!hasChromeRuntime) {
    pill.textContent = "Standalone";
    pill.className = "backend-pill offline";
    return;
  }
  chrome.runtime.sendMessage({ type: "CHECK_HEALTH" }, (res) => {
    if (chrome.runtime.lastError || !res || !res.online) {
      pill.textContent = "Offline";
      pill.className = "backend-pill offline";
    } else {
      pill.textContent = "Online";
      pill.className = "backend-pill online";
    }
  });
}

function showView(name) {
  $("viewLoading").style.display = name === "loading" ? "flex" : "none";
  $("viewIdle").style.display = name === "idle" ? "flex" : "none";
  $("viewError").style.display = name === "error" ? "flex" : "none";
  $("viewResult").style.display = name === "result" ? "block" : "none";
}

function riskColorVar(level) {
  const map = { LOW: "var(--low)", MEDIUM: "var(--medium)", HIGH: "var(--high)", CRITICAL: "var(--critical)" };
  return map[(level || "").toUpperCase()] || "var(--unknown)";
}

function renderAssessment(data) {
  currentData = data;
  showView("result");

  const assessment = data.assessment || {};
  const level = (assessment.overall_risk_level || data.risk_level || "UNKNOWN").toUpperCase();
  const idx = assessment.heuristic_risk_index ?? Math.round((data.phishing_probability || 0) * 100);

  let host = "—";
  try { host = new URL(data.url).hostname; } catch { host = data.url || "—"; }

  $("siteDomain").textContent = host;
  $("siteUrl").textContent = data.url || "—";
  $("lastScanTime").textContent = data.timestamp ? `Last scan: ${new Date(data.timestamp).toLocaleTimeString()}` : "Last scan: —";

  const badge = $("overallRiskBadge");
  badge.textContent = level;
  badge.className = `risk-badge risk-${level}`;

  $("heuristicScoreVal").textContent = `${idx}/100`;
  $("heuristicScoreVal").style.color = riskColorVar(level);
  $("urlModelScore").textContent = assessment.url_model_threat_probability != null ? `${(assessment.url_model_threat_probability * 100).toFixed(1)}%` : "N/A";
  $("domModelScore").textContent = assessment.dom_model_threat_probability != null ? `${(assessment.dom_model_threat_probability * 100).toFixed(1)}%` : "N/A";

  $("riskMeterFill").style.width = `${Math.max(4, Math.min(100, idx))}%`;
  $("riskMeterFill").style.background = riskColorVar(level);
  $("recommendedAction").textContent = assessment.recommended_action || data.verdict || "";

  // Render 6 separated dimensions
  const dims = assessment.dimensions || {};
  const dimMeta = [
    ["connection_security", "Connection Security"],
    ["phishing_risk", "Phishing Risk"],
    ["malware_risk", "Malware Risk"],
    ["credential_risk", "Credential Risk"],
    ["payment_risk", "Payment Risk"],
    ["deceptive_behavior_risk", "Deceptive UX"],
  ];
  $("dimensionsGrid").innerHTML = dimMeta.map(([key, label]) => {
    const info = dims[key] || { level: "UNKNOWN" };
    const lv = (info.level || "UNKNOWN").toUpperCase();
    return `
      <div class="dim-card">
        <span class="dim-name">${label}</span>
        <span class="dim-level risk-${lv}">${lv}</span>
      </div>
    `;
  }).join("");

  // Evidence & unavailable disclosures
  const ev = assessment.evidence && assessment.evidence.length ? assessment.evidence : (data.top_indicators || []);
  $("evidenceList").innerHTML = ev.length
    ? ev.map(item => `<li>${item}</li>`).join("")
    : "<li>No elevated risk indicators detected.</li>";

  const unavail = assessment.unavailable_signals || [];
  if (unavail.length) {
    $("unavailableNote").style.display = "block";
    $("unavailableNote").textContent = `Inaccessible / unavailable signals: ${unavail.join(", ")}`;
  } else {
    $("unavailableNote").style.display = "none";
  }

  // DOM & telemetry grid
  const dom = data.features?.dom_features || {};
  const domRows = [
    ["HTTPS Transport", dom.is_https ? "Yes" : "No"],
    ["Mixed Content", dom.mixed_content_count ?? 0],
    ["Password Inputs", dom.num_password_fields ?? 0],
    ["External Forms", dom.external_forms_count ?? 0],
    ["Payment Inputs", dom.num_payment_inputs ?? 0],
    ["iFrames", dom.num_iframes ?? 0],
    ["Uninspected iFrames", dom.cross_origin_iframes_uninspected ?? 0],
    ["External Scripts", dom.num_external_scripts ?? 0],
    ["Inline Suspicious JS", dom.suspicious_inline_js_count ?? 0],
    ["Fake Download CTAs", dom.fake_download_button_count ?? 0],
    ["Meta/JS Redirects", (dom.meta_refresh_redirects || 0) + (dom.js_redirect_indicators || 0)],
    ["Popup Triggers", dom.popup_trigger_count ?? 0],
  ];
  $("domSignalsGrid").innerHTML = domRows.map(([k, v]) => `
    <div class="sig-item"><span class="sig-key">${k}</span><span class="sig-val">${v}</span></div>
  `).join("");

  $("xaiOutput").style.display = "none";
  $("feedbackStatus").style.display = "none";
}

// Evidence accordion
$("toggleEvidenceBtn")?.addEventListener("click", () => {
  const body = $("evidenceBody");
  const open = body.style.display !== "none";
  body.style.display = open ? "none" : "block";
  $("evidenceChevron").textContent = open ? "▸" : "▾";
});

// Explain Verdict
$("explainBtn")?.addEventListener("click", () => {
  if (!currentData || !hasChromeRuntime) return;
  const out = $("xaiOutput");
  out.style.display = "block";
  out.textContent = "Generating explanation…";
  let host = "";
  try { host = new URL(currentData.url).hostname; } catch {}
  chrome.runtime.sendMessage({
    type: "EXPLAIN_URL",
    url: currentData.url,
    hostname: host,
    is_phishing: currentData.is_phishing,
    risk_level: currentData.risk_level,
    phishing_probability: currentData.phishing_probability,
    features: currentData.features || {},
    assessment: currentData.assessment || null,
  }, (res) => {
    out.textContent = res?.explanation || res?.error || "Explanation unavailable.";
  });
});

// User-confirmed Trusted Domain
$("trustDomainBtn")?.addEventListener("click", async () => {
  if (!currentData?.url) return;
  let host = "";
  try { host = new URL(currentData.url).hostname.toLowerCase(); } catch { return; }
  if (!window.confirm(`Confirm marking '${host}' as trusted? Future automatic warnings for this host will be suppressed until cleared.`)) {
    return;
  }
  const res = await store.get("trusted_domains");
  const list = Array.isArray(res.trusted_domains) ? res.trusted_domains : [];
  if (!list.includes(host)) list.push(host);
  await store.set({ trusted_domains: list });
  $("feedbackStatus").style.display = "block";
  $("feedbackStatus").textContent = `Trusted '${host}' locally.`;
});

// Feedback reporting
function sendFeedback(reportType) {
  if (!currentData?.url || !hasChromeRuntime) return;
  chrome.runtime.sendMessage({
    type: "SUBMIT_FEEDBACK",
    payload: {
      url: currentData.url,
      report_type: reportType,
      reported_risk_level: currentData.risk_level,
      notes: "Submitted from WebShield AI Chrome extension popup.",
    },
  }, (res) => {
    $("feedbackStatus").style.display = "block";
    $("feedbackStatus").textContent = res?.ok
      ? "Report recorded for human verification."
      : `Feedback failed: ${res?.error || "Backend offline"}`;
  });
}

$("reportFpBtn")?.addEventListener("click", () => sendFeedback("false_positive"));
$("reportMissedBtn")?.addEventListener("click", () => sendFeedback("missed_suspicious"));

// History tab
async function renderHistory() {
  const res = await store.get("scan_history");
  const list = Array.isArray(res.scan_history) ? res.scan_history : [];
  if (!list.length) {
    $("historyList").innerHTML = `<p class="view-sub">No local scan history recorded yet.</p>`;
    return;
  }
  $("historyList").innerHTML = list.map(item => `
    <div class="hist-item">
      <div style="min-width:0">
        <div class="hist-host">${item.hostname || item.url}</div>
        <div class="hist-time">${new Date(item.timestamp).toLocaleString()}</div>
      </div>
      <span class="risk-badge risk-${item.risk_level || "UNKNOWN"}">${item.risk_level || "UNKNOWN"}</span>
    </div>
  `).join("");
}

$("clearHistoryBtn")?.addEventListener("click", async () => {
  await store.set({ scan_history: [] });
  renderHistory();
});

// Rescan flow
async function triggerRescan() {
  if (!hasChromeTabs) { showView("idle"); return; }
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.id || !tab.url || !tab.url.startsWith("http")) {
    showView("idle");
    return;
  }
  await store.remove(`tab_${tab.id}`);
  chrome.runtime.sendMessage({ type: "RESCAN_TAB", tabId: tab.id });
  showView("loading");
  pollTab(`tab_${tab.id}`);
}

$("rescanBtn")?.addEventListener("click", triggerRescan);
$("idleScanBtn")?.addEventListener("click", triggerRescan);
$("retryErrorBtn")?.addEventListener("click", triggerRescan);

function pollTab(key, attempt = 0) {
  if (attempt > 24) {
    $("errorMsg").textContent = "Scan timed out. Check backend connection.";
    showView("error");
    return;
  }
  setTimeout(async () => {
    const res = await store.get(key);
    const data = res[key];
    if (!data || data.status === "loading") { pollTab(key, attempt + 1); return; }
    if (data.status === "error") {
      $("errorMsg").textContent = data.error || "Backend unreachable.";
      showView("error");
      return;
    }
    if (data.status === "done") renderAssessment(data);
  }, 500);
}

async function bootstrap() {
  await initTheme();
  checkBackendHealth();

  if (!hasChromeTabs) {
    showView("idle");
    return;
  }
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.id || !tab.url || !tab.url.startsWith("http")) {
    showView("idle");
    return;
  }
  const key = `tab_${tab.id}`;
  const res = await store.get(key);
  const data = res[key];
  if (!data) showView("idle");
  else if (data.status === "loading") { showView("loading"); pollTab(key); }
  else if (data.status === "error") { $("errorMsg").textContent = data.error || "Backend unreachable."; showView("error"); }
  else if (data.status === "done") renderAssessment(data);
}

bootstrap();
