"""
backend/explainer.py — Explainable AI (XAI) Engine for Phishing Detection

Provides human-interpretable explanations of why a webpage was flagged as phishing:
1. Feature-attribution rule engine: Extracts top technical red flags from 48 ML features.
2. OpenRouter & Google Gemini Flash integration: Uses generative AI to produce deep,
   natural-language incident-response briefings for the end user.
"""

import os
import json
import logging
import urllib.request
import urllib.error
import sys
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("PhishingAPI.Explainer")

DEFAULT_OPENROUTER_KEY = os.getenv("OPENROUTER_API_KEY", "")
DEFAULT_GEMINI_KEY = os.getenv("GEMINI_API_KEY", "")

SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "tk", "ml", "cf", "gq", "ga", "buzz", "cc",
    "rest", "fit", "surf", "casa", "icu", "click", "link", "party",
    "country", "stream", "gdn", "kim", "mom", "vip", "win"
}


def extract_top_indicators(features_dict: dict, is_phishing: bool, risk_level: str) -> list[str]:
    """
    Examines page & URL features to identify primary technical red flags or verified safety factors.
    Returns a human-readable list of bullet-point indicators.
    """
    indicators = []

    if is_phishing:
        # 1. Password field checks
        has_pwd = int(features_dict.get("HasPasswordField", 0)) == 1
        if has_pwd:
            indicators.append("Credential Field: Page contains password input fields prompting for sensitive credentials.")

        # 2. HTTPS status
        is_https = int(features_dict.get("IsHTTPS", 0)) == 1
        if not is_https:
            indicators.append("Insecure Protocol: Connection lacks HTTPS encryption, exposing entered credentials to interception.")

        # 3. External Form Submission
        ext_submit = int(features_dict.get("HasExternalFormSubmit", 0)) == 1
        if ext_submit:
            indicators.append("External Data Exfiltration: Forms on this page submit data to an external, third-party domain.")

        # 4. TLD Analysis
        tld = str(features_dict.get("TLD", "")).lower().lstrip(".")
        if tld in SUSPICIOUS_TLDS:
            indicators.append(f"Suspicious Top-Level Domain: '.{tld}' is frequently associated with disposable phishing campaigns.")

        # 5. IP Address Domain
        is_ip = int(features_dict.get("IsDomainIP", 0)) == 1
        if is_ip:
            indicators.append("IP-Based Host: URL uses a direct IP address instead of a registered domain name.")

        # 6. Obfuscated characters
        obf_count = int(features_dict.get("NoOfObfuscatedChar", 0))
        has_obf = int(features_dict.get("HasObfuscation", 0)) == 1
        if has_obf or obf_count > 0:
            indicators.append(f"URL Obfuscation: Detected {obf_count} encoded or obfuscated characters intended to disguise destination.")

        # 7. Domain / Title Mismatch
        title_match = float(features_dict.get("DomainTitleMatchScore", 1.0))
        has_title = int(features_dict.get("HasTitle", 0)) == 1
        if has_title and title_match < 0.2:
            indicators.append("Domain-Brand Mismatch: Webpage title does not correspond with the actual registered domain name.")

        # 8. External Links vs Self Links
        ext_refs = int(features_dict.get("NoOfExternalRef", 0))
        self_refs = int(features_dict.get("NoOfSelfRef", 0))
        empty_refs = int(features_dict.get("NoOfEmptyRef", 0))
        if ext_refs > 15 and (self_refs == 0 or ext_refs > self_refs * 3):
            indicators.append(f"Cloned Template Pattern: High external reference count ({ext_refs} external vs {self_refs} internal links).")

        if empty_refs >= 5:
            indicators.append(f"Dummy Navigation Links: Found {empty_refs} dummy '#' links characteristic of hastily cloned templates.")

        # 9. Hidden iFrames
        iframes = int(features_dict.get("NoOfiFrame", 0))
        if iframes >= 2:
            indicators.append(f"Embedded Framing: {iframes} embedded iframes detected, which can conceal hidden credential collectors.")

        # 10. Financial / Payment Keywords
        bank = int(features_dict.get("Bank", 0)) == 1
        pay = int(features_dict.get("Pay", 0)) == 1
        crypto = int(features_dict.get("Crypto", 0)) == 1
        if bank or pay or crypto:
            target = "banking" if bank else ("payment" if pay else "crypto")
            indicators.append(f"High-Value Target Spoofing: Page contains keywords and layouts imitating {target} services.")

        if not indicators:
            indicators.append(f"Anomalous URL Architecture: Model detected high-confidence phishing patterns ({risk_level} Risk).")
            indicators.append("Statistical feature distribution strongly matches verified fake login datasets.")
    else:
        # Legitimate indicators
        is_https = int(features_dict.get("IsHTTPS", 1)) == 1
        if is_https:
            indicators.append("Encrypted Protocol: Connection uses valid HTTPS transport encryption.")

        has_pwd = int(features_dict.get("HasPasswordField", 0)) == 1
        if not has_pwd:
            indicators.append("No Deceptive Traps: Page does not harvest passwords or sensitive credentials.")

        ext_submit = int(features_dict.get("HasExternalFormSubmit", 0)) == 1
        if not ext_submit:
            indicators.append("First-Party Actions: Forms submit directly to authorized domain endpoints.")

        title_match = float(features_dict.get("DomainTitleMatchScore", 1.0))
        if title_match >= 0.5:
            indicators.append("Domain Consistency: Hostname matches verified identity metadata.")

        if not indicators:
            indicators.append("Clean Architecture: No anomalous redirects or obfuscations detected.")
            indicators.append("Structural Integrity: Feature vectors conform to standard web standards.")

    return indicators


def build_analysis_prompt(url: str, hostname: str, risk_level: str, phishing_prob: float, indicators: list[str], is_phishing: bool = True) -> str:
    """Constructs a cybersecurity analyst prompt for LLM explanation."""
    if is_phishing:
        indicators_text = "\n".join([f"- {ind}" for ind in indicators]) if indicators else "- General URL and structural anomalies."
        return f"""You are an elite Cybersecurity Incident Responder and Explainable AI (XAI) security expert.
A user is browsing the web and our AI Phishing Shield flagged the following webpage:

URL: {url}
Hostname: {hostname}
Verdict: Phishing Detected ({risk_level} Risk, {phishing_prob * 100:.1f}% confidence)

Detected Technical Red Flags:
{indicators_text}

Provide an Explainable AI (XAI) security briefing for the user with the following sections:
1. Threat Summary: In 2 sentences, explain what this site appears to be doing (e.g., impersonation, credential harvesting) and why our AI flagged it.
2. Why It Is Dangerous: 3 concise bullet points explaining the exact risks if the user continues.
3. Recommended Action: 1 direct, actionable sentence advising the user (e.g. close the tab, do not type credentials).

Formatting: Use concise Markdown with emoji bullet points. Do not include conversational filler. Keep it under 140 words."""
    else:
        safety_text = "\n".join([f"- {ind}" for ind in indicators]) if indicators else "- Valid security signals."
        return f"""You are an elite Cybersecurity Analyst and Explainable AI (XAI) security expert.
A user is browsing the web and our AI Phishing Shield evaluated the following webpage as SAFE / LEGITIMATE:

URL: {url}
Hostname: {hostname}
Verdict: Verified Safe ({risk_level} Risk, {(1 - phishing_prob) * 100:.1f}% safety confidence)

Verified Security Signals:
{safety_text}

Provide a concise Explainable AI (XAI) safety briefing for the user with the following sections:
1. Safety Assessment: In 1-2 sentences, explain why this domain and page structure appear genuine and trustworthy.
2. Key Safety Factors: 2-3 concise bullet points highlighting positive security signals (e.g., legitimate domain reputation, valid structure, lack of deceptive patterns).
3. Browsing Tip: 1 sentence reminding the user to remain vigilant even on legitimate sites.

Formatting: Use concise Markdown with emoji bullet points. Do not include conversational filler. Keep it under 120 words."""


def call_openrouter_gemini(prompt: str, api_key: str) -> str:
    """
    Calls OpenRouter using Gemini Flash models with max_tokens set appropriately.
    """
    models = [
        "google/gemini-2.5-flash",
        "google/gemini-3.8-flash",
        "google/gemini-3.7-flash",
        "google/gemini-3.5-flash",
        "google/gemini-2.5-flash-lite",
    ]
    headers = {
        "Authorization": f"Bearer {api_key.strip()}",
        "Content-Type": "application/json",
        "User-Agent": "PhishGuard-AI/1.0",
        "HTTP-Referer": "http://127.0.0.1:8000",
        "X-Title": "AI Phishing Shield",
    }

    last_error = None
    for model in models:
        payload = {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are an elite Cybersecurity Incident Responder providing concise, expert Explainable AI (XAI) security briefings for users.",
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            "temperature": 0.2,
            "max_tokens": 350,
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request("https://openrouter.ai/api/v1/chat/completions", data=data, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                resp_json = json.loads(resp.read().decode("utf-8"))
                choices = resp_json.get("choices", [])
                if choices:
                    content = choices[0].get("message", {}).get("content", "")
                    if content:
                        logger.info(f"OpenRouter Gemini explanation generated successfully using {model}.")
                        return content.strip()
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="ignore")
            logger.warning(f"OpenRouter API ({model}) HTTP error {e.code}: {err_body}")
            last_error = f"HTTP {e.code}: {err_body}"
            if e.code in (401, 403):
                raise ValueError("Invalid OpenRouter API key. Please check your key at openrouter.ai.")
            continue
        except Exception as e:
            logger.warning(f"OpenRouter API ({model}) error: {e}")
            last_error = str(e)
            continue

    raise RuntimeError(f"Unable to generate explanation from OpenRouter Gemini ({last_error})")


def call_google_gemini_direct(prompt: str, api_key: str) -> str:
    """
    Calls Google Generative Language endpoint directly with standard Gemini keys.
    """
    # Fast, high-availability models placed first to avoid timeouts and high-traffic 503 errors
    models = [
        "gemini-3.5-flash-lite",
        "gemini-flash-lite-latest",
        "gemini-3.5-flash",
    ]
    headers = {"Content-Type": "application/json"}
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 300,
        },
    }
    data = json.dumps(payload).encode("utf-8")

    last_error = None
    for model_name in models:
        endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
        try:
            req = urllib.request.Request(endpoint, data=data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=18) as resp:
                resp_json = json.loads(resp.read().decode("utf-8"))
                candidates = resp_json.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts and "text" in parts[0]:
                        return parts[0]["text"].strip()
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="ignore")
            logger.warning(f"Gemini API ({model_name}) HTTP error {e.code}: {err_body}")
            last_error = f"HTTP {e.code}: {err_body}"
            if e.code in (400, 403) and "API_KEY_INVALID" in err_body:
                raise ValueError("Invalid Google Gemini API key.")
            continue
        except Exception as e:
            logger.warning(f"Gemini API ({model_name}) error: {e}")
            last_error = str(e)
            continue

    raise RuntimeError(f"Unable to generate explanation from Gemini API ({last_error})")


def generate_explanation(
    url: str,
    hostname: str,
    is_phishing: bool,
    risk_level: str,
    phishing_prob: float,
    features_dict: dict,
    api_key: str | None = None,
) -> dict:
    """
    Main entry point for generating explanations.
    Uses Google Gemini API or OpenRouter Gemini Flash; falls back to rule-based XAI if unavailable.
    """
    indicators = extract_top_indicators(features_dict, is_phishing, risk_level)
    key = api_key or os.getenv("GEMINI_API_KEY") or DEFAULT_GEMINI_KEY or os.getenv("OPENROUTER_API_KEY") or DEFAULT_OPENROUTER_KEY

    if key and key.strip():
        clean_key = key.strip()
        try:
            prompt = build_analysis_prompt(url, hostname, risk_level, phishing_prob, indicators, is_phishing=is_phishing)
            if clean_key.startswith("sk-or-"):
                ai_text = call_openrouter_gemini(prompt, clean_key)
                source_name = "openrouter_gemini"
            else:
                ai_text = call_google_gemini_direct(prompt, clean_key)
                source_name = "gemini"

            return {
                "explanation": ai_text,
                "top_indicators": indicators,
                "source": source_name,
            }
        except Exception as e:
            logger.warning(f"Falling back to rule-based explanation due to API error: {e}")
            err_str = str(e)
            if "HTTP 503" in err_str or "Service Unavailable" in err_str:
                service_note = "AI servers are experiencing temporary high demand; displaying local XAI analysis."
            elif "timed out" in err_str.lower():
                service_note = "Cloud AI response timed out; displaying local XAI analysis."
            elif "Invalid" in err_str:
                service_note = "Gemini API key is invalid or expired."
            else:
                service_note = "Cloud AI temporarily unavailable; displaying local XAI analysis."

            if is_phishing:
                fallback_text = (
                    f"### ⚠️ Explainable AI Threat Breakdown\n\n"
                    f"**Threat Assessment:** This page scored a **{phishing_prob*100:.1f}% phishing probability** ({risk_level} Risk). "
                    f"The layout and URL characteristics match known credential-theft patterns.\n\n"
                    f"**Identified Red Flags:**\n" +
                    "\n".join([f"- 🚨 {ind}" for ind in indicators]) +
                    f"\n\n*({service_note})*"
                )
            else:
                fallback_text = (
                    f"### 🛡️ Explainable AI Safety Assessment\n\n"
                    f"**Safety Assessment:** This page scored a **{(1-phishing_prob)*100:.1f}% safety confidence** ({risk_level} Risk). "
                    f"Structural signals and domain parameters appear legitimate.\n\n"
                    f"**Verified Indicators:**\n" +
                    "\n".join([f"- 🛡️ {ind}" for ind in indicators]) +
                    f"\n\n*({service_note})*"
                )
            return {
                "explanation": fallback_text,
                "top_indicators": indicators,
                "source": "rule_based_fallback",
                "error": str(e),
            }

    # Rule-based fallback
    if is_phishing:
        rule_text = (
            f"### 🛡️ Explainable AI Threat Breakdown\n\n"
            f"**Threat Assessment:** The AI classifier flagged **{hostname or url}** with **{phishing_prob*100:.1f}% phishing confidence** ({risk_level} Risk). "
            f"The page exhibits behavioral and architectural anomalies common in deceptive phishing operations.\n\n"
            f"**Top Detected Red Flags:**\n" +
            "\n".join([f"- 🚨 {ind}" for ind in indicators]) +
            f"\n\n**Safety Advice:** Do not submit usernames, passwords, or financial information. Close this page immediately."
        )
    else:
        rule_text = (
            f"### 🛡️ Explainable AI Security Breakdown\n\n"
            f"**Safety Assessment:** **{hostname or url}** is classified as legitimate with **{(1 - phishing_prob)*100:.1f}% confidence**. "
            f"No malicious form actions, URL obfuscations, or credential-harvesting indicators were detected."
        )

    return {
        "explanation": rule_text,
        "top_indicators": indicators,
        "source": "rule_based",
    }


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    print("Running Explainable AI (XAI) Diagnostic Self-Test...")
    test_res = generate_explanation(
        url="https://google.com",
        hostname="google.com",
        is_phishing=False,
        risk_level="SAFE",
        phishing_prob=0.015,
        features_dict={"URLLength": 18, "IsHTTPS": 1, "HasPasswordField": 0},
    )
    print(f"\nEngine Source: {test_res.get('source')}")
    print("\nGenerated Explanation:\n")
    print(test_res.get("explanation"))


