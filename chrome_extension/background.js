/**
 * background.js — WebShield AI Chrome Extension Service Worker (Manifest V3, v3.0)
 *
 * Security & Reliability Features:
 * - Cache keys bound to normalized URL + DOM fingerprint + backend model version + schema version
 * - Automatic navigation invalidation on tab URL changes (`chrome.tabs.onUpdated`)
 * - Never suppresses security scans or critical alerts (eliminates persistent Trust bypass)
 * - Explicitly distinguishes LOCAL_NETWORK_UNVERIFIED, UNKNOWN, and OFFLINE states
 * - Configurable API base URL in chrome.storage.local; zero embedded secrets or cookie access
 */

"use strict";

importScripts("utils.js");

const U = globalThis.WebShieldUtils;
const DEFAULT_API_BASE_URL = "http://127.0.0.1:8000";
const CACHE_TTL_MS = 5 * 60 * 1000;
const MODEL_VER_TTL_MS = 10 * 60 * 1000;
const MIN_SCAN_INTERVAL_MS = 1000;
const MAX_CACHE_ENTRIES = 150;

const inFlightScans = new Map();
const lastScanTimestamps = new Map();
let cachedModelVersionInfo = { version: "v3.0.0", fetchedAt: 0 };

async function getApiBaseUrl() {
  const res = await chrome.storage.local.get("api_base_url");
  const raw = (res.api_base_url || DEFAULT_API_BASE_URL).trim().replace(/\/+$/, "");
  return raw || DEFAULT_API_BASE_URL;
}

function extractHostname(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

async function getActiveModelVersion(baseUrl) {
  const now = Date.now();
  if (now - cachedModelVersionInfo.fetchedAt < MODEL_VER_TTL_MS && cachedModelVersionInfo.version) {
    return cachedModelVersionInfo.version;
  }
  try {
    const resp = await fetch(`${baseUrl}/version`, { method: "GET" });
    if (resp.ok) {
      const json = await resp.json();
      const ver = `${json.url_model_version || "v3.0.0"}-${json.dom_model_version || "v3.0.0"}`;
      cachedModelVersionInfo = { version: ver, fetchedAt: now };
      return ver;
    }
  } catch {
    // Keep last known or default
  }
  return cachedModelVersionInfo.version || "v3.0.0";
}

async function pruneStaleCacheIfNeeded() {
  const all = await chrome.storage.local.get(null);
  const cacheKeys = Object.keys(all).filter((k) => k.startsWith("cache_"));
  if (cacheKeys.length <= MAX_CACHE_ENTRIES) return;
  const sorted = cacheKeys
    .map((k) => ({ key: k, ts: Number(all[k]?.timestamp || 0) }))
    .sort((a, b) => a.ts - b.ts);
  const toRemove = sorted.slice(0, cacheKeys.length - MAX_CACHE_ENTRIES).map((x) => x.key);
  if (toRemove.length) await chrome.storage.local.remove(toRemove);
}

async function appendScanHistory(entry) {
  const res = await chrome.storage.local.get("scan_history");
  const history = Array.isArray(res.scan_history) ? res.scan_history : [];
  const filtered = history.filter((item) => item.url !== entry.url);
  filtered.unshift({
    url: entry.url,
    hostname: extractHostname(entry.url),
    risk_level: entry.risk_level,
    operational_status: entry.operational_status || entry.assessment?.operational_status || "Unknown",
    heuristic_risk_index: entry.heuristic_risk_index ?? entry.assessment?.heuristic_risk_index ?? null,
    phishing_probability: entry.phishing_probability ?? null,
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

  // Explicit Local/Private Network handling: never misreport as LOW/Safe
  if (U.isLocalNetworkHost(host)) {
    const localData = {
      status: "done",
      url: pageUrl,
      timestamp: Date.now(),
      is_phishing: false,
      phishing_probability: null,
      legitimate_probability: null,
      heuristic_risk_index: null,
      operational_status: "LOCAL_NETWORK_UNVERIFIED",
      connection_security: "LOCAL_NETWORK_UNVERIFIED",
      verdict: `LOCAL NETWORK UNVERIFIED (${host})`,
      risk_level: "UNKNOWN",
      whitelisted: false,
      top_indicators: ["Loopback or private network host detected; external reputation and threat scans skipped."],
      assessment: {
        overall_risk_level: "UNKNOWN",
        phishing_probability: null,
        heuristic_risk_index: null,
        operational_status: "LOCAL_NETWORK_UNVERIFIED",
        connection_security: "LOCAL_NETWORK_UNVERIFIED",
        dimensions: {
          connection_security: { level: "UNKNOWN", status: "LOCAL_NETWORK_UNVERIFIED", evidence: [] },
          phishing_risk: { level: "UNKNOWN", score: null, evidence: [] },
          malware_risk: { level: "UNKNOWN", score: null, evidence: [] },
          credential_risk: { level: "UNKNOWN", score: null, evidence: [] },
          payment_risk: { level: "UNKNOWN", score: null, evidence: [] },
          deceptive_behavior_risk: { level: "UNKNOWN", score: null, evidence: [] },
        },
        evidence: ["Website not inspected externally: local/private network destination (LOCAL_NETWORK_UNVERIFIED)."],
        unavailable_signals: ["external_threat_intel", "rdap_domain_age"],
        recommended_action: "Local or private host. External reputation checks do not apply.",
      },
      features,
    };
    await chrome.storage.local.set({ [`tab_${tabId}`]: localData });
    updateBadge(tabId, "UNKNOWN", "LOCAL_NETWORK_UNVERIFIED");
    return { ok: true, local: true };
  }

  const now = Date.now();
  const prevTs = lastScanTimestamps.get(`${tabId}:${pageUrl}`) || 0;
  if (!force && now - prevTs < MIN_SCAN_INTERVAL_MS) {
    return { ok: true, throttled: true };
  }
  lastScanTimestamps.set(`${tabId}:${pageUrl}`, now);

  const baseUrl = await getApiBaseUrl();
  const modelVersion = await getActiveModelVersion(baseUrl);
  const cacheKey = U.buildCacheKey({
    url: pageUrl,
    domFeatures: features?.dom_features,
    modelVersion,
  });

  if (!force) {
    const cachedObj = await chrome.storage.local.get(cacheKey);
    const cached = cachedObj[cacheKey];
    if (U.isCacheEntryValid(cached, modelVersion, now, CACHE_TTL_MS)) {
      const storageData = { ...cached, status: "done", features };
      await chrome.storage.local.set({ [`tab_${tabId}`]: storageData });
      updateBadge(tabId, storageData.risk_level, storageData.operational_status);
      chrome.tabs.sendMessage(tabId, { type: "PHISHING_RESULT", data: storageData }, () => { void chrome.runtime.lastError; });
      return { ok: true, cached: true };
    }
  }

  await chrome.storage.local.set({
    [`tab_${tabId}`]: { status: "loading", url: pageUrl, timestamp: now },
  });

  try {
    let promise = inFlightScans.get(cacheKey);
    if (!promise) {
      promise = callPredictAPI(baseUrl, features).finally(() => inFlightScans.delete(cacheKey));
      inFlightScans.set(cacheKey, promise);
    }
    const result = await promise;
    const storageData = {
      status: "done",
      url: pageUrl,
      model_version: modelVersion,
      timestamp: Date.now(),
      is_phishing: result.is_phishing,
      phishing_probability: result.phishing_probability,
      legitimate_probability: result.legitimate_probability,
      heuristic_risk_index: result.heuristic_risk_index ?? result.assessment?.heuristic_risk_index ?? null,
      operational_status: result.operational_status || result.assessment?.operational_status || "Unknown",
      connection_security: result.connection_security || result.assessment?.connection_security || "UNKNOWN",
      model_availability: result.model_availability || result.assessment?.model_availability || {},
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
    pruneStaleCacheIfNeeded().catch(() => {});
    await appendScanHistory(storageData);
    updateBadge(tabId, result.risk_level, storageData.operational_status);

    chrome.tabs.sendMessage(tabId, { type: "PHISHING_RESULT", data: storageData }, () => {
      void chrome.runtime.lastError;
    });

    if (result.risk_level === "HIGH" || result.risk_level === "CRITICAL") {
      const idx = result.heuristic_risk_index ?? result.assessment?.heuristic_risk_index ?? "N/A";
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
        status: "offline",
        operational_status: "OFFLINE",
        risk_level: "UNKNOWN",
        url: pageUrl,
        timestamp: Date.now(),
        error: err.message || "Backend service offline or unreachable.",
      },
    });
    updateBadge(tabId, "UNKNOWN", "OFFLINE");
    return { error: err.message };
  }
}

async function callPredictAPI(base, features) {
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
      phishing_probability: message.phishing_probability ?? null,
      heuristic_risk_index: message.heuristic_risk_index ?? null,
      features: message.features || {},
      assessment: message.assessment || null,
    }),
  });
  if (!resp.ok) {
    throw new Error(`Explain API returned ${resp.status}`);
  }
  return await resp.json();
}

function updateBadge(tabId, riskLevel, operationalStatus = "") {
  if (operationalStatus === "LOCAL_NETWORK_UNVERIFIED") {
    chrome.action.setBadgeText({ tabId, text: "LOC" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#64748b" });
    return;
  }
  if (operationalStatus === "OFFLINE") {
    chrome.action.setBadgeText({ tabId, text: "OFF" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#475569" });
    return;
  }
  const lv = String(riskLevel || "UNKNOWN").toUpperCase();
  let text = "?";
  let color = "#64748b";
  if (lv === "LOW") {
    text = "✓";
    color = "#10b981";
  } else if (lv === "MEDIUM") {
    text = "!";
    color = "#f59e0b";
  } else if (lv === "HIGH") {
    text = "!!";
    color = "#f97316";
  } else if (lv === "CRITICAL") {
    text = "!!!";
    color = "#e11d48";
  }
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.url) {
    chrome.storage.local.remove(`tab_${tabId}`);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove(`tab_${tabId}`);
});
