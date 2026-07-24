/**
 * background.js — Chrome Extension Service Worker
 *
 * Receives the ANALYZE_PAGE message from content.js,
 * calls the FastAPI /predict endpoint with the extracted features,
 * stores the result in chrome.storage.local (keyed by tab ID),
 * and updates the extension's badge icon to show the risk level.
 */

"use strict";

const API_BASE_URL = "http://127.0.0.1:8000";

// ─────────────────────────────────────────────────────────────────────────────
// Message handler
// ─────────────────────────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "ANALYZE_PAGE") {
    const tabId = sender.tab?.id;
    const pageUrl = message.url;
    const features = message.features;

    if (!tabId || !features) {
      sendResponse({ error: "Missing tab ID or features" });
      return;
    }

    // Store a "loading" state immediately so popup can show a spinner
    chrome.storage.local.set({
      [`tab_${tabId}`]: {
        status: "loading",
        url: pageUrl,
        timestamp: Date.now(),
      },
    });

    // Call the FastAPI backend
    callPredictAPI(features)
      .then((result) => {
        const storageData = {
          status: "done",
          url: pageUrl,
          timestamp: Date.now(),
          is_phishing: result.is_phishing,
          phishing_probability: result.phishing_probability,
          legitimate_probability: result.legitimate_probability,
          verdict: result.verdict,
          risk_level: result.risk_level,
        };

        chrome.storage.local.set({ [`tab_${tabId}`]: storageData });
        updateBadge(tabId, result.risk_level, result.is_phishing);

        // ── Send result back to the content script (in-page banner) ──
        chrome.tabs.sendMessage(tabId, {
          type: "PHISHING_RESULT",
          data: storageData,
        }).catch(() => {}); // Tab may have navigated — ignore

        // ── Native OS notification for phishing pages ──
        if (result.is_phishing) {
          const pct = Math.round((result.phishing_probability || 0) * 100);
          chrome.notifications.create(`phish_${tabId}_${Date.now()}`, {
            type: "basic",
            iconUrl: "icons/icon128.png",
            title: `⚠️ Phishing Page Detected! [${result.risk_level} RISK]`,
            message: `${pct}% confidence this page is a phishing attempt. Do NOT enter your credentials!`,
            priority: 2,
          });
        }

        sendResponse({ ok: true });
      })
      .catch((err) => {
        const errorData = {
          status: "error",
          url: pageUrl,
          timestamp: Date.now(),
          error: err.message || "Network error — is the API server running?",
        };
        chrome.storage.local.set({ [`tab_${tabId}`]: errorData });
        updateBadgeError(tabId);
        sendResponse({ error: err.message });
      });

    // Return true to keep the message channel open for async sendResponse
    return true;
  }

  // Handle popup requesting a re-scan of the current tab
  if (message.type === "RESCAN_TAB") {
    const tabId = message.tabId;
    if (tabId) {
      // Re-inject the content script to re-scan
      chrome.scripting
        .executeScript({
          target: { tabId: tabId },
          files: ["content.js"],
        })
        .catch((err) => {
          console.error("[Background] Re-inject failed:", err);
        });
    }
    sendResponse({ ok: true });
    return true;
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// API call
// ─────────────────────────────────────────────────────────────────────────────

async function callPredictAPI(features) {
  const response = await fetch(`${API_BASE_URL}/predict`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json",
    },
    body: JSON.stringify(features),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`API returned ${response.status}: ${text}`);
  }

  return response.json();
}

// ─────────────────────────────────────────────────────────────────────────────
// Badge helpers
// ─────────────────────────────────────────────────────────────────────────────

function updateBadge(tabId, riskLevel, isPhishing) {
  let text = "✓";
  let color = "#22c55e"; // green

  if (isPhishing) {
    if (riskLevel === "HIGH") {
      text = "!!!";
      color = "#ef4444"; // red
    } else if (riskLevel === "MEDIUM") {
      text = "!";
      color = "#f97316"; // orange
    } else {
      text = "?";
      color = "#eab308"; // yellow
    }
  }

  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

function updateBadgeError(tabId) {
  chrome.action.setBadgeText({ tabId, text: "ERR" });
  chrome.action.setBadgeBackgroundColor({ tabId, color: "#6b7280" }); // gray
}

// ─────────────────────────────────────────────────────────────────────────────
// Clean up stored data when a tab is closed
// ─────────────────────────────────────────────────────────────────────────────

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove(`tab_${tabId}`);
});
