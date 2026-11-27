/**
 * background.js — WebShield AI Chrome Extension Service Worker (Manifest V3)
 *
 * Features:
 * - Configurable API base URL stored in chrome.storage.local (supports local dev & HTTPS prod)
 * - TTL response caching, request throttling, and active-request deduplication
 * - User-confirmed trusted domains registry
 * - Local scan history persistence (max 100 entries, clearable)
 * - Feedback reporting (/feedback) and backend connectivity status (/health)
 * - No API secrets or direct LLM keys stored or invoked in extension code
 */

"use strict";

const DEFAULT_API_BASE_URL = "http://127.0.0.1:8000";
const CACHE_TTL_MS = 5 * 60 * 1000;
const MIN_SCAN_INTERVAL_MS = 1200;

const inFlightScans = new Map();
const lastScanTimestamps = new Map();

async function getApiBaseUrl() {
  const res = await chrome.storage.local.get("api_base_url");
  const raw = (res.api_base_url || DEFAULT_API_BASE_URL).trim().replace(/\/+$/, "");
  return raw || DEFAULT_API_BASE_URL;
}

async function getTrustedDomains() {
  const res = await chrome.storage.local.get("trusted_domains");
  return Array.isArray(res.trusted_domains) ? res.trusted_domains : [];
}

function extractHostname(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

async function appendScanHistory(entry) {
  const res = await chrome.storage.local.get("scan_history");
  const history = Array.isArray(res.scan_history) ? res.scan_history : [];
  const filtered = history.filter(item => item.url !== entry.url);
  filtered.unshift({
    url: entry.url,
    hostname: extractHostname(entry.url),
    risk_level: entry.risk_level,
    heuristic_risk_index: entry.assessment?.heuristic_risk_index ?? Math.round((entry.phishing_probability || 0) * 100),
    timestamp: entry.timestamp,
  });
  await chrome.storage.local.set({ scan_history: filtered.slice(0, 100) });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "ANALYZE_PAGE") {
    const tabId = sender.tab?.id;
    const pageUrl = message.url;
    const features = message.features;
    const force = Boolean(message.force);

    if (!tabId || !features) {
      sendResponse({ error: "Missing tab ID or features." });
      return;
    }

    handleAnalyzePage(tabId, pageUrl, features, force)
      .then((out) => sendResponse(out))
      .catch((err) => sendResponse({ error: err.message }));
    return true;
  }

  if (message.type === "EXPLAIN_URL") {
    handleExplainRequest(message)
      .then((res) => sendResponse(res))
      .catch((err) => sendResponse({ error: err.message }));
    return true;
  }

  if (message.type === "CHECK_HEALTH") {
    getApiBaseUrl().then(async (base) => {
      try {
        const resp = await fetch(`${base}/health`, { method: "GET" });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const json = await resp.json();
        sendResponse({ online: true, baseUrl: base, health: json });
      } catch (e) {
        sendResponse({ online: false, baseUrl: base, error: e.message });
      }
    });
    return true;
  }

  if (message.type === "SUBMIT_FEEDBACK") {
    getApiBaseUrl().then(async (base) => {
      try {
        const resp = await fetch(`${base}/feedback`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(message.payload),
        });
        const json = await resp.json();
        sendResponse({ ok: resp.ok, data: json });
      } catch (e) {
        sendResponse({ ok: false, error: e.message });
      }
    });
    return true;
  }

  if (message.type === "RESCAN_TAB") {
    const tabId = message.tabId;
    if (!tabId) {
      sendResponse({ ok: false });
      return true;
    }
    chrome.tabs.get(tabId, (tab) => {
      if (chrome.runtime.lastError || !tab || !tab.url || !tab.url.startsWith("http")) {
        sendResponse({ ok: false, reason: "Non-web page" });
        return;
      }
      chrome.tabs.sendMessage(tabId, { type: "TRIGGER_RESCAN" }, () => {
        if (chrome.runtime.lastError) {
          chrome.tabs.reload(tabId);
        }
      });
      sendResponse({ ok: true });
    });
    return true;
  }
});

async function handleAnalyzePage(tabId, pageUrl, features, force) {
  const host = extractHostname(pageUrl);
  const trusted = await getTrustedDomains();

  if (!force && trusted.includes(host)) {
    const trustedResult = {
      status: "done",
      url: pageUrl,
      timestamp: Date.now(),
      is_phishing: false,
      phishing_probability: 0.0,
      legitimate_probability: 1.0,
      verdict: `User-trusted domain (${host})`,
      risk_level: "LOW",
      whitelisted: true,
      user_trusted: true,
      top_indicators: ["Marked as trusted by user confirmation."],
      assessment: {
        overall_risk_level: "LOW",
        heuristic_risk_index: 0,
        dimensions: {
          connection_security: { level: pageUrl.startsWith("https") ? "LOW" : "MEDIUM", status: pageUrl.startsWith("https") ? "SECURE_HTTPS" : "INSECURE_HTTP", evidence: [] },
          phishing_risk: { level: "LOW", score: 0.0, evidence: [] },
          malware_risk: { level: "LOW", score: 0.0, evidence: [] },
          credential_risk: { level: "LOW", score: 0.0, evidence: [] },
          payment_risk: { level: "LOW", score: 0.0, evidence: [] },
          deceptive_behavior_risk: { level: "LOW", score: 0.0, evidence: [] },
        },
        evidence: ["Domain explicitly confirmed as trusted by the user."],
        unavailable_signals: features.dom_features?.unavailable_signals || [],
        recommended_action: "User-confirmed trusted domain.",
      },
      features,
    };
    await chrome.storage.local.set({ [`tab_${tabId}`]: trustedResult });
    updateBadge(tabId, "LOW");
    return { ok: true };
  }

  // Throttle rapid duplicate triggers on the same tab/URL
  const now = Date.now();
  const prevTs = lastScanTimestamps.get(`${tabId}:${pageUrl}`) || 0;
  if (!force && now - prevTs < MIN_SCAN_INTERVAL_MS) {
    return { ok: true, throttled: true };
  }
  lastScanTimestamps.set(`${tabId}:${pageUrl}`, now);

  // Check TTL cache
  const cacheKey = `cache_${pageUrl}`;
  if (!force) {
    const cachedObj = await chrome.storage.local.get(cacheKey);
    const cached = cachedObj[cacheKey];
    if (cached && now - cached.timestamp < CACHE_TTL_MS) {
      const storageData = { ...cached, status: "done", features };
      await chrome.storage.local.set({ [`tab_${tabId}`]: storageData });
      updateBadge(tabId, storageData.risk_level);
      chrome.tabs.sendMessage(tabId, { type: "PHISHING_RESULT", data: storageData }, () => { void chrome.runtime.lastError; });
      return { ok: true, cached: true };
    }
  }

  await chrome.storage.local.set({
    [`tab_${tabId}`]: { status: "loading", url: pageUrl, timestamp: now },
  });

  try {
    let promise = inFlightScans.get(pageUrl);
    if (!promise) {
      promise = callPredictAPI(features).finally(() => inFlightScans.delete(pageUrl));
      inFlightScans.set(pageUrl, promise);
    }
    const result = await promise;
    const storageData = {
      status: "done",
      url: pageUrl,
      timestamp: Date.now(),
      is_phishing: result.is_phishing,
      phishing_probability: result.phishing_probability,
      legitimate_probability: result.legitimate_probability,
      verdict: result.verdict,
      risk_level: result.risk_level,
      whitelisted: result.whitelisted || false,
      top_indicators: result.top_indicators || [],
      assessment: result.assessment || null,
      features,
    };

    await chrome.storage.local.set({
      [`tab_${tabId}`]: storageData,
      [cacheKey]: storageData,
    });
    await appendScanHistory(storageData);
    updateBadge(tabId, result.risk_level);

    chrome.tabs.sendMessage(tabId, { type: "PHISHING_RESULT", data: storageData }, () => {
      void chrome.runtime.lastError;
    });

    if (result.risk_level === "HIGH" || result.risk_level === "CRITICAL") {
      const idx = result.assessment?.heuristic_risk_index ?? Math.round((result.phishing_probability || 0) * 100);
      chrome.notifications.create(`ws_${tabId}_${Date.now()}`, {
        type: "basic",
        iconUrl: "icons/icon128.png",
        title: `WebShield ${result.risk_level} RISK (${idx}/100)`,
        message: `${host}: ${result.assessment?.recommended_action || "Avoid entering credentials or payment info."}`,
        priority: 2,
      });
    }
    return { ok: true };
  } catch (err) {
    await chrome.storage.local.set({
      [`tab_${tabId}`]: {
        status: "error",
        url: pageUrl,
        timestamp: Date.now(),
        error: err.message || "Backend service unreachable.",
      },
    });
    updateBadgeError(tabId);
    return { error: err.message };
  }
}

async function callPredictAPI(features) {
  const base = await getApiBaseUrl();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 9000);
  try {
    const response = await fetch(`${base}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify(features),
      signal: controller.signal,
    });
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`API ${response.status}: ${text}`);
    }
    return await response.json();
  } finally {
    clearTimeout(timer);
  }
}

async function handleExplainRequest(message) {
  const base = await getApiBaseUrl();
  const resp = await fetch(`${base}/explain`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Accept": "application/json" },
    body: JSON.stringify({
      url: message.url || "",
      hostname: message.hostname || "",
      is_phishing: Boolean(message.is_phishing),
      risk_level: message.risk_level || "LOW",
      phishing_probability: message.phishing_probability ?? 0.5,
      features: message.features || {},
      assessment: message.assessment || null,
    }),
  });
  if (!resp.ok) {
    throw new Error(`Explain API returned ${resp.status}`);
  }
  return await resp.json();
}

function updateBadge(tabId, riskLevel) {
  const lv = (riskLevel || "LOW").toUpperCase();
  let text = "✓";
  let color = "#10b981";
  if (lv === "CRITICAL") {
    text = "!!!";
    color = "#e11d48";
  } else if (lv === "HIGH") {
    text = "!!";
    color = "#f97316";
  } else if (lv === "MEDIUM") {
    text = "!";
    color = "#f59e0b";
  } else if (lv === "UNKNOWN") {
    text = "?";
    color = "#64748b";
  }
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

function updateBadgeError(tabId) {
  chrome.action.setBadgeText({ tabId, text: "ERR" });
  chrome.action.setBadgeBackgroundColor({ tabId, color: "#6b7280" });
}

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove(`tab_${tabId}`);
});
