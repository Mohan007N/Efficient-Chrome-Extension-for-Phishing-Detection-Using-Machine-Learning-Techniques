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
          whitelisted: result.whitelisted || false,
          top_indicators: result.top_indicators || [],
          features: features,
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

  // Handle Explainable AI request
  if (message.type === "EXPLAIN_URL") {
    chrome.storage.local.get("gemini_api_key", (stored) => {
      const apiKey = message.gemini_api_key || stored.gemini_api_key || DEFAULT_GEMINI_KEY;
      const payload = {
        url: message.url || "",
        hostname: message.hostname || "",
        is_phishing: message.is_phishing !== false,
        risk_level: message.risk_level || "HIGH",
        phishing_probability: message.phishing_probability || 0.95,
        features: message.features || {},
        gemini_api_key: apiKey,
      };

      callExplainAPI(payload)
        .then((res) => sendResponse(res))
        .catch((err) => sendResponse({ error: err.message }));
    });
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
// API calls
// ─────────────────────────────────────────────────────────────────────────────

const DEFAULT_GEMINI_KEY = "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";

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

async function callExplainAPI(payload) {
  try {
    const response = await fetch(`${API_BASE_URL}/explain`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (response.ok) {
      return await response.json();
    }
  } catch (err) {
    console.warn("[Background] Backend /explain request failed, attempting direct fallback:", err);
  }

  // Direct client-side fallback if backend is unreachable
  const key = payload.gemini_api_key || DEFAULT_GEMINI_KEY;
  if (key) {
    return await callGeminiDirectly({ ...payload, gemini_api_key: key });
  }

  return {
    explanation: "⚠️ Backend API is offline and no API key is configured. Please start the server (python backend/main.py).",
    top_indicators: payload.features ? ["High risk detection triggered."] : [],
    source: "offline_fallback",
  };
}

async function callGeminiDirectly(payload) {
  const key = (payload.gemini_api_key || DEFAULT_GEMINI_KEY).trim();
  const prompt = `You are a Cybersecurity Incident Responder. Explain why this website was flagged as phishing:
Target URL: ${payload.url}
Phishing Probability: ${((payload.phishing_probability || 0.9) * 100).toFixed(1)}%
Risk Level: ${payload.risk_level || "HIGH"}

Provide a concise 3-point briefing:
1. Threat Summary: Why this page is suspicious (e.g. credential harvesting or brand spoofing).
2. Key Red Flags: 3 concise bullet points identifying the technical danger signs.
3. User Action: 1 direct safety advisory.
Keep it under 130 words with clear bullet points.`;

  // Check if OpenRouter key
  if (key.startsWith("sk-or-")) {
    const models = ["google/gemini-2.5-flash", "google/gemini-3.8-flash", "google/gemini-3.7-flash", "google/gemini-3.5-flash"];
    for (const model of models) {
      try {
        const resp = await fetch("https://openrouter.ai/api/v1/chat/completions", {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${key}`,
            "Content-Type": "application/json",
            "HTTP-Referer": "http://127.0.0.1:8000",
            "X-Title": "AI Phishing Shield",
          },
          body: JSON.stringify({
            model: model,
            messages: [
              { role: "system", content: "You are an elite Cybersecurity Incident Responder providing concise Explainable AI briefings." },
              { role: "user", content: prompt }
            ],
            temperature: 0.2,
            max_tokens: 350,
          }),
        });

        if (resp.ok) {
          const json = await resp.json();
          const text = json.choices?.[0]?.message?.content;
          if (text) {
            return {
              explanation: text,
              top_indicators: ["OpenRouter Gemini Flash threat analysis generated."],
              source: "openrouter_direct",
            };
          }
        }
      } catch (e) {
        console.warn(`[Background] OpenRouter ${model} error:`, e);
      }
    }
  }

  // Google Generative Language direct endpoint
  const googleModels = ["gemini-2.0-flash", "gemini-1.5-flash"];
  for (const model of googleModels) {
    try {
      const resp = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: { temperature: 0.2, maxOutputTokens: 400 },
          }),
        }
      );
      if (resp.ok) {
        const json = await resp.json();
        const text = json.candidates?.[0]?.content?.parts?.[0]?.text;
        if (text) {
          return {
            explanation: text,
            top_indicators: ["Direct Google Gemini threat analysis generated."],
            source: "gemini_direct",
          };
        }
      }
    } catch (err) {
      console.warn(`[Background] Direct Gemini ${model} failed:`, err);
    }
  }

  throw new Error("AI explanation request failed. Please check your OpenRouter / Gemini key.");
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
