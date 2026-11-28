/**
 * popup.js — WebShield AI Popup Dashboard Controller (Manifest V3, v3.0)
 *
 * Strictly separates calibrated ML phishing_probability from Heuristic Risk Index,
 * HTML-escapes all rendered DOM/evidence text, displays LOCAL_NETWORK_UNVERIFIED / OFFLINE / UNKNOWN
 * states accurately, and omits permanent warning/scan bypasses.
 */

"use strict";

const DEFAULT_API_BASE = "http://127.0.0.1:8000";
const U = (typeof window !== "undefined" && window.WebShieldUtils) || {
  escapeHtml: (v) => String(v ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"),
};

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
let activeTabId = null;
let activePollToken = 0;

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

$("settingsBtn")?.addEventListener("click", async () => {
  const panel = $("settingsPanel");
  const open = panel.style.display !== "none";
  panel.style.display = open ? "none" : "block";
  if (!open) await refreshSettings();
});
$("settingsCloseBtn")?.addEventListener("click", () => { $("settingsPanel").style.display = "none"; });

async function refreshSettings() {
  const data = await store.get(["api_base_url", "api_key"]);
  $("apiBaseInput").value = data.api_base_url || DEFAULT_API_BASE;
  if ($("apiKeyInput")) {
    $("apiKeyInput").value = data.api_key || "";
  }
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

$("saveApiKeyBtn")?.addEventListener("click", async () => {
  const keyVal = ($("apiKeyInput")?.value || "").trim();
  if (keyVal) {
    await store.set({ api_key: keyVal });
    $("apiSaveStatus").textContent = "API key saved locally.";
  } else {
    await store.remove("api_key");
    $("apiSaveStatus").textContent = "API key cleared.";
  }
});

$("resetApiBtn")?.addEventListener("click", async () => {
  await store.remove("api_base_url");
  $("apiBaseInput").value = DEFAULT_API_BASE;
  $("apiSaveStatus").textContent = "Reset to localhost.";
  checkBackendHealth();
});

$("clearCacheBtn")?.addEventListener("click", async () => {
  if (!hasChromeStorage) return;
  const all = await chrome.storage.local.get(null);
  const cacheKeys = Object.keys(all).filter((k) => k.startsWith("cache_") || k === "trusted_domains");
  if (cacheKeys.length) await chrome.storage.local.remove(cacheKeys);
  $("apiSaveStatus").textContent = `Cleared ${cacheKeys.length} cached entry(s).`;
});

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
    } else if (res.health?.degraded) {
      pill.textContent = "Degraded";
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

function derivePredictionName(level, opStatus, explicitLabel = "") {
  if (explicitLabel) return explicitLabel;
  if (opStatus === "LOCAL_NETWORK_UNVERIFIED") return "Local Network (Unverified)";
  if (opStatus === "Blocked") return "Blocked (Firewall / DNS)";
  if (opStatus === "Unreachable") return "Unreachable Host";
  if (level === "LOW") return "Real (Legitimate)";
  if (level === "MEDIUM") return "Caution (Suspicious)";
  if (level === "HIGH" || level === "CRITICAL") return "Fake / Phishing";
  return "Unverified";
}

function renderShapDrivers(attributions) {
  const container = $("shapDriversList");
  if (!container) return;
  if (!Array.isArray(attributions) || attributions.length === 0) {
    container.innerHTML = `<div class="xai-empty">No ML feature attributions available for this target.</div>`;
    return;
  }
  const maxAbs = Math.max(
    0.05,
    ...attributions.map((a) => Math.abs(Number(a.risk_contribution || 0)))
  );
  container.innerHTML = attributions.slice(0, 5).map((a) => {
    const label = U.escapeHtml(a.label || String(a.feature || "Signal").replace(/_/g, " "));
    const valTxt = U.escapeHtml(Number.isFinite(Number(a.value)) ? Number(a.value) : (a.value ?? "—"));
    const layer = a.model_layer ? `<span class="shap-meta">(${U.escapeHtml(a.model_layer)} • val ${valTxt})</span>` : `<span class="shap-meta">(val ${valTxt})</span>`;
    const contrib = Number(a.risk_contribution || 0);
    const dir = String(a.direction || "");
    let cls = "neutral";
    let tag = `Weight ${contrib.toFixed(3)}`;
    if (dir === "increases_risk" || (dir !== "reduces_risk" && dir !== "model_importance" && contrib > 0)) {
      cls = "risk";
      tag = `+${Math.abs(contrib).toFixed(3)} Risk`;
    } else if (dir === "reduces_risk" || contrib < 0) {
      cls = "safe";
      tag = `-${Math.abs(contrib).toFixed(3)} Safe`;
    }
    const pct = Math.max(8, Math.min(100, Math.round((Math.abs(contrib) / maxAbs) * 100)));
    return `
      <div class="shap-row">
        <div class="shap-row-top">
          <div class="shap-feat">${label}${layer}</div>
          <span class="shap-delta ${cls}">${U.escapeHtml(tag)}</span>
        </div>
        <div class="shap-bar-track"><div class="shap-bar-fill ${cls}" style="width:${pct}%"></div></div>
      </div>
    `;
  }).join("");
}

function renderAssessment(data) {
  currentData = data;
  showView("result");

  const assessment = data.assessment || {};
  const level = String(assessment.overall_risk_level || data.risk_level || "UNKNOWN").toUpperCase();
  const opStatus = assessment.operational_status || data.operational_status || "Unknown";
  const predLabel = derivePredictionName(level, opStatus, assessment.prediction_label || data.prediction_label || "");
  const idx = assessment.heuristic_risk_index !== undefined ? assessment.heuristic_risk_index : data.heuristic_risk_index;
  const mlProb = assessment.phishing_probability !== undefined ? assessment.phishing_probability : data.phishing_probability;
  const conf = assessment.confidence !== undefined ? assessment.confidence : data.confidence;

  let host = "—";
  try { host = new URL(data.url).hostname; } catch { host = data.url || "—"; }

  $("siteDomain").textContent = host;
  $("siteUrl").textContent = data.url || "—";
  $("lastScanTime").textContent = data.timestamp ? `Last scan: ${new Date(data.timestamp).toLocaleTimeString()}` : "Last scan: —";

  const predCard = $("predictionCard");
  if (predCard) {
    predCard.className = `prediction-card tone-${level}`;
  }
  const predEl = $("predictionLabelVal");
  if (predEl) {
    predEl.textContent = predLabel;
    predEl.style.color = riskColorVar(level);
  }

  const badge = $("overallRiskBadge");
  badge.textContent = `${level} RISK`;
  badge.className = `risk-badge risk-${level}`;

  if (idx !== null && idx !== undefined) {
    $("heuristicScoreVal").textContent = `${idx}/100`;
    $("riskMeterFill").style.width = `${Math.max(4, Math.min(100, idx))}%`;
  } else {
    $("heuristicScoreVal").textContent = "N/A";
    $("riskMeterFill").style.width = "10%";
  }
  $("heuristicScoreVal").style.color = riskColorVar(level);
  $("riskMeterFill").style.background = riskColorVar(level);

  $("operationalStatusLabel").textContent = `Status: ${opStatus}`;
  $("mlPhishProbVal").textContent = mlProb != null ? `${(Number(mlProb) * 100).toFixed(1)}%` : "N/A";
  $("urlModelScore").textContent = assessment.url_model_threat_probability != null ? `${(assessment.url_model_threat_probability * 100).toFixed(1)}%` : "N/A";
  $("domModelScore").textContent = assessment.dom_model_threat_probability != null ? `${(assessment.dom_model_threat_probability * 100).toFixed(1)}%` : "N/A";
  if ($("confidenceVal")) {
    $("confidenceVal").textContent = conf != null ? `${Math.round(Number(conf) * 100)}%` : "N/A";
  }
  $("recommendedAction").textContent = assessment.recommended_action || data.verdict || "";

  const shapAttrs = assessment.shap_attributions || data.shap_attributions || [];
  renderShapDrivers(shapAttrs);

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
    const lv = U.escapeHtml(String(info.level || "UNKNOWN").toUpperCase());
    const safeStatus = info.status ? ` (${U.escapeHtml(info.status)})` : "";
    return `
      <div class="dim-card">
        <span class="dim-name">${U.escapeHtml(label)}${safeStatus}</span>
        <span class="dim-level risk-${lv}">${lv}</span>
      </div>
    `;
  }).join("");

  const ev = assessment.evidence && assessment.evidence.length ? assessment.evidence : (data.top_indicators || []);
  $("evidenceList").innerHTML = ev.length
    ? ev.map(item => `<li>${U.escapeHtml(item)}</li>`).join("")
    : "<li>No elevated risk indicators observed.</li>";

  const unavail = assessment.unavailable_signals || [];
  if (unavail.length) {
    $("unavailableNote").style.display = "block";
    $("unavailableNote").textContent = `Inaccessible / unavailable signals: ${unavail.join(", ")}`;
  } else {
    $("unavailableNote").style.display = "none";
  }

  const diag = data.diagnostics || assessment.diagnostics || {};
  const diagRows = [
    ["URL Model Prob", diag.url_model_probability != null ? Number(diag.url_model_probability).toFixed(4) : "N/A"],
    ["DOM Model Prob", diag.dom_model_probability != null ? Number(diag.dom_model_probability).toFixed(4) : "N/A"],
    ["Ensemble Prob", diag.ensemble_probability != null ? Number(diag.ensemble_probability).toFixed(4) : "N/A"],
    ["URL Risk Used", diag.url_risk_score != null ? Number(diag.url_risk_score).toFixed(4) : "N/A"],
    ["DOM Risk Used", diag.dom_risk_score != null ? Number(diag.dom_risk_score).toFixed(4) : "N/A"],
    ["Brand Score", diag.brand_impersonation_score != null ? Number(diag.brand_impersonation_score).toFixed(2) : "0.00"],
    ["Tranco Rank", diag.threat_intelligence_result?.tranco_rank ?? "Unranked"],
    ["User-Hosted", diag.threat_intelligence_result?.is_hosted_user_content ? "Yes" : "No"],
    ["Query Tempered", diag.url_query_tempered ? "Yes" : "No"],
    ["Thresholds", diag.thresholds ? `${diag.thresholds.url_model}/${diag.thresholds.dom_model}` : "N/A"],
  ];
  if ($("devDiagGrid")) {
    $("devDiagGrid").innerHTML = diagRows.map(([k, v]) => `
      <div class="sig-item"><span class="sig-key">${U.escapeHtml(k)}</span><span class="sig-val">${U.escapeHtml(v)}</span></div>
    `).join("");
  }

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
    <div class="sig-item"><span class="sig-key">${U.escapeHtml(k)}</span><span class="sig-val">${U.escapeHtml(v)}</span></div>
  `).join("");

  $("xaiOutput").style.display = "none";
  $("xaiOutput").innerHTML = "";
  $("feedbackStatus").style.display = "none";
}

$("toggleEvidenceBtn")?.addEventListener("click", () => {
  const body = $("evidenceBody");
  const open = body.style.display !== "none";
  body.style.display = open ? "none" : "block";
  $("evidenceChevron").textContent = open ? "▸" : "▾";
});

$("toggleDevDiagBtn")?.addEventListener("click", () => {
  const body = $("devDiagBody");
  if (!body) return;
  const open = body.style.display !== "none";
  body.style.display = open ? "none" : "block";
  if ($("devDiagChevron")) $("devDiagChevron").textContent = open ? "▸" : "▾";
});

$("explainBtn")?.addEventListener("click", () => {
  if (!currentData || !hasChromeRuntime) return;
  const out = $("xaiOutput");
  out.style.display = "flex";
  out.innerHTML = `<div class="xai-empty">Generating structured AI explanation…</div>`;
  let host = "";
  try { host = new URL(currentData.url).hostname; } catch {}
  chrome.runtime.sendMessage({
    type: "EXPLAIN_URL",
    url: currentData.url,
    hostname: host,
    is_phishing: currentData.is_phishing,
    risk_level: currentData.risk_level,
    phishing_probability: currentData.phishing_probability,
    heuristic_risk_index: currentData.heuristic_risk_index,
    features: currentData.features || {},
    assessment: currentData.assessment || null,
  }, (res) => {
    if (chrome.runtime.lastError || !res || (res.error && !res.explanation)) {
      out.innerHTML = `<div class="xai-empty">${U.escapeHtml(chrome.runtime.lastError?.message || res?.error || "Explanation unavailable.")}</div>`;
      return;
    }
    if (Array.isArray(res.feature_attributions) && res.feature_attributions.length) {
      renderShapDrivers(res.feature_attributions);
    }
    const sourceBadge = res.source === "groq" ? "Groq AI + SHAP" : "SHAP + Rule XAI";
    const summaryText = res.summary || res.explanation || "Explanation generated.";
    const signals = Array.isArray(res.key_signals) && res.key_signals.length
      ? res.key_signals
      : (res.top_indicators || []);
    const actionText = res.recommended_action || "";
    const sigHtml = signals.length
      ? `<ul class="xai-signals">${signals.slice(0, 5).map((s) => `<li>${U.escapeHtml(s)}</li>`).join("")}</ul>`
      : "";
    const actHtml = actionText
      ? `<div class="xai-action-box">${U.escapeHtml(actionText)}</div>`
      : "";
    out.innerHTML = `
      <div class="xai-source-row">
        <span class="xai-source-badge">${U.escapeHtml(sourceBadge)}</span>
        <span class="section-sub">${U.escapeHtml(res.prediction_label || "")}</span>
      </div>
      <p class="xai-summary">${U.escapeHtml(summaryText)}</p>
      ${sigHtml}
      ${actHtml}
    `;
  });
});

function sendFeedback(reportType) {
  if (!currentData?.url || !hasChromeRuntime) return;
  chrome.runtime.sendMessage({
    type: "SUBMIT_FEEDBACK",
    payload: {
      url: currentData.url,
      report_type: reportType,
      reported_risk_level: currentData.risk_level,
      notes: "Submitted from WebShield AI Chrome extension v3.0 popup.",
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

async function renderHistory() {
  const res = await store.get("scan_history");
  const list = Array.isArray(res.scan_history) ? res.scan_history : [];
  if (!list.length) {
    $("historyList").innerHTML = `<p class="view-sub">No local scan history recorded yet.</p>`;
    return;
  }
  $("historyList").innerHTML = list.map(item => {
    const safeHost = U.escapeHtml(item.hostname || item.url);
    const safeLv = U.escapeHtml(item.risk_level || "UNKNOWN");
    const predText = derivePredictionName(item.risk_level, item.operational_status, item.prediction_label || "");
    const safePred = U.escapeHtml(predText);
    const safeTime = U.escapeHtml(new Date(item.timestamp).toLocaleString());
    return `
      <div class="hist-item">
        <div style="min-width:0">
          <div class="hist-host">${safeHost}</div>
          <div class="hist-time">${safeTime} • ${safePred}</div>
        </div>
        <span class="risk-badge risk-${safeLv}">${safeLv}</span>
      </div>
    `;
  }).join("");
}

$("clearHistoryBtn")?.addEventListener("click", async () => {
  await store.set({ scan_history: [] });
  renderHistory();
});

async function triggerRescan() {
  if (!hasChromeTabs) { showView("idle"); return; }
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.id || !tab.url || !tab.url.startsWith("http")) {
    showView("idle");
    return;
  }
  activeTabId = tab.id;
  currentData = null;
  const key = `tab_${tab.id}`;
  await store.set({ [key]: { status: "loading", url: tab.url, timestamp: Date.now() } });
  chrome.runtime.sendMessage({ type: "RESCAN_TAB", tabId: tab.id }, (resp) => {
    if (chrome.runtime.lastError) {
      $("errorMsg").textContent = chrome.runtime.lastError.message || "Could not contact tab scanner.";
      showView("error");
    }
  });
  showView("loading");
  pollTab(key, 0, ++activePollToken);
}

$("rescanBtn")?.addEventListener("click", triggerRescan);
$("reverifyBtn")?.addEventListener("click", triggerRescan);
$("idleScanBtn")?.addEventListener("click", triggerRescan);
$("retryErrorBtn")?.addEventListener("click", triggerRescan);

function pollTab(key, attempt = 0, token = activePollToken) {
  if (token !== activePollToken) return;
  if (attempt > 34) {
    $("errorMsg").textContent = "Scan timed out. Check backend connection (OFFLINE).";
    showView("error");
    return;
  }
  setTimeout(async () => {
    if (token !== activePollToken) return;
    const res = await store.get(key);
    const data = res[key];
    if (!data || data.status === "loading") { pollTab(key, attempt + 1, token); return; }
    if (data.status === "error" || data.status === "offline") {
      $("errorMsg").textContent = data.error || "Backend offline or unreachable.";
      showView("error");
      return;
    }
    if (data.status === "done") renderAssessment(data);
  }, 450);
}

if (hasChromeStorage && chrome.storage.onChanged) {
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName !== "local" || !activeTabId) return;
    const ch = changes[`tab_${activeTabId}`];
    if (!ch || !ch.newValue) return;
    const nextData = ch.newValue;
    if (nextData.status === "done") {
      activePollToken++;
      renderAssessment(nextData);
    } else if (nextData.status === "error" || nextData.status === "offline") {
      activePollToken++;
      $("errorMsg").textContent = nextData.error || "Backend offline or unreachable.";
      showView("error");
    } else if (nextData.status === "loading" && (!currentData || currentData.url !== nextData.url)) {
      showView("loading");
    }
  });
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
  activeTabId = tab.id;
  const key = `tab_${tab.id}`;
  const res = await store.get(key);
  const data = res[key];
  if (!data || (data.url && data.url !== tab.url)) {
    // Missing or stale result (e.g., extension reloaded on open tab or SPA navigation just happened): auto-scan immediately
    await triggerRescan();
  } else if (data.status === "loading") {
    showView("loading");
    pollTab(key, 0, ++activePollToken);
  } else if (data.status === "error" || data.status === "offline") {
    $("errorMsg").textContent = data.error || "Backend offline or unreachable.";
    showView("error");
  } else if (data.status === "done") {
    renderAssessment(data);
  }
}

bootstrap();
