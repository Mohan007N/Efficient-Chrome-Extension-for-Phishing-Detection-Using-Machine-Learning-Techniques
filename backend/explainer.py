"""
backend/explainer.py — Multi-Layer Explainable AI (XAI) & SHAP Attribution Engine (v3.0)

Combines:
1. Calibrated-wrapper-aware SHAP (TreeExplainer) / feature-importance attributions resolved strictly
   via `model.classes_` (`0 = Phishing/Malicious`, `1 = Benign/Legitimate`).
2. Dimension-specific rule explanations (Credential, Payment, Malware, Deceptive, Transport, Brand).
3. Threat intelligence evidence & separated ML probability vs heuristic risk index disclosure.
4. Optional Groq LLM synthesis with deterministic fallback.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import urllib.error
import urllib.request

from dotenv import load_dotenv

from src.evaluate import resolve_class_indices
from src.features import SUSPICIOUS_COMMERCE_TLDS, detect_brand_impersonation

load_dotenv(override=True)
logger = logging.getLogger("PhishingAPI.Explainer")

DEFAULT_GROQ_KEY = os.getenv("GROQ_API_KEY", "")
SUSPICIOUS_TLDS = SUSPICIOUS_COMMERCE_TLDS

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False


def _unwrap_calibrated_or_pipeline_estimator(model):
    """Extract underlying fitted estimator from CalibratedClassifierCV or sklearn Pipeline if wrapped."""
    inner = model
    if hasattr(inner, "calibrated_classifiers_") and inner.calibrated_classifiers_:
        cc = inner.calibrated_classifiers_[0]
        if hasattr(cc, "estimator") and cc.estimator is not None:
            inner = cc.estimator
        elif hasattr(cc, "base_estimator") and cc.base_estimator is not None:
            inner = cc.base_estimator
    if hasattr(inner, "named_steps") and inner.named_steps:
        last_step = list(inner.named_steps.values())[-1]
        inner = last_step
    return inner


def compute_shap_attributions(model, X_row, top_k: int = 5) -> list[dict]:
    """
    Compute top SHAP feature contributions toward threat risk (`0 = Phishing/Malicious`) for a single row.
    Unwraps `CalibratedClassifierCV` cleanly and respects `model.classes_` sign conventions.
    """
    if model is None or X_row is None or getattr(X_row, "empty", True):
        return []

    try:
        phish_idx, _ = resolve_class_indices(model)
    except Exception:
        phish_idx = 0

    base_model = _unwrap_calibrated_or_pipeline_estimator(model)
    cols = list(X_row.columns)

    if SHAP_AVAILABLE:
        try:
            explainer = shap.TreeExplainer(base_model)
            sv = explainer.shap_values(X_row)
            if isinstance(sv, list):
                vals = sv[phish_idx][0]
            elif getattr(sv, "ndim", 0) == 3:
                vals = sv[0, :, phish_idx]
            elif getattr(sv, "ndim", 0) == 2:
                # 2D binary TreeExplainer returns log-odds for positive class `1` (benign) -> invert for class 0 if phish_idx == 0
                vals = -sv[0] if phish_idx == 0 else sv[0]
            else:
                vals = sv
            pairs = []
            for idx, col in enumerate(cols):
                contrib = float(vals[idx])
                pairs.append({
                    "feature": col,
                    "value": float(X_row.iloc[0, idx]),
                    "risk_contribution": round(contrib, 4),
                    "direction": "increases_risk" if contrib > 0 else "reduces_risk",
                })
            pairs.sort(key=lambda x: abs(x["risk_contribution"]), reverse=True)
            return pairs[:top_k]
        except Exception as e:
            logger.debug(f"SHAP TreeExplainer skipped: {e}")

    if hasattr(base_model, "feature_importances_"):
        importances = base_model.feature_importances_
        ranked = sorted(
            zip(cols, importances, X_row.iloc[0].tolist()),
            key=lambda t: float(t[1]),
            reverse=True,
        )[:top_k]
        return [
            {
                "feature": col,
                "value": float(val),
                "risk_contribution": round(float(imp), 4),
                "direction": "model_importance",
            }
            for col, imp, val in ranked
        ]
    return []


def extract_top_indicators(
    features_dict: dict,
    is_phishing: bool,
    risk_level: str,
    backend_indicators: list[str] | None = None,
) -> list[str]:
    """Extract readable technical indicators from features and optional assessment evidence."""
    indicators: list[str] = []
    if backend_indicators:
        for item in backend_indicators:
            if item and item not in indicators:
                indicators.append(item)

    if not indicators and features_dict:
        hostname = str(features_dict.get("hostname", features_dict.get("Domain", "")))
        imp_score, matched_brand = detect_brand_impersonation(hostname)
        if imp_score >= 0.80 and matched_brand:
            indicators.append(f"Hostname resembles protected brand '{matched_brand}' on an unofficial domain.")

        raw_https = features_dict.get("IsHTTPS")
        if raw_https is None:
            raw_https = features_dict.get("is_https")
        is_https = True if raw_https is None else int(bool(raw_https))
        has_pwd = int(features_dict.get("HasPasswordField", features_dict.get("num_password_fields", 0)) or 0) > 0
        ext_sub = int(features_dict.get("HasExternalFormSubmit", features_dict.get("has_external_form_action", 0)) or 0) > 0

        if not is_https:
            indicators.append("Insecure HTTP connection detected (transport lacks TLS encryption).")
        if has_pwd and ext_sub:
            indicators.append("High credential risk: password form submits to a different external domain.")
        elif has_pwd and not is_https:
            indicators.append("Credential form served over unencrypted HTTP connection.")

        if not indicators:
            if is_phishing or risk_level in ("HIGH", "CRITICAL"):
                indicators.append(f"Elevated multi-factor risk patterns observed ({risk_level} risk).")
            else:
                indicators.append("No suspicious indicators observed across checked dimensions.")
    return indicators


def build_analysis_prompt(
    url: str,
    hostname: str,
    risk_level: str,
    phishing_prob: float | None,
    indicators: list[str],
    assessment: dict | None = None,
    attributions: list[dict] | None = None,
    heuristic_risk_index: int | None = None,
) -> str:
    """Build an accurate, evidence-based cybersecurity explanation prompt for Groq AI."""
    ind_txt = "\n".join(f"- {x}" for x in indicators) if indicators else "- No strong risk signals detected."
    dims_txt = ""
    if assessment and assessment.get("dimensions"):
        dims_txt = "\nSeparated Risk Dimensions:\n" + "\n".join(
            f"- {k}: {v.get('level')} ({v.get('status') or v.get('score')})"
            for k, v in assessment["dimensions"].items()
        )
    attr_txt = ""
    if attributions:
        attr_txt = "\nTop Model Feature Contributions:\n" + "\n".join(
            f"- {a['feature']}={a['value']} ({a['direction']}, {a['risk_contribution']})"
            for a in attributions[:5]
        )

    prob_str = f"{phishing_prob:.2%}" if phishing_prob is not None else "Unavailable (not computed)"
    h_idx = heuristic_risk_index if heuristic_risk_index is not None else (assessment or {}).get("heuristic_risk_index")
    h_str = f"{h_idx}/100" if h_idx is not None else "Unavailable"

    return (
        "You are a Cybersecurity Safety Analyst writing a clear, factual website risk briefing.\n"
        "Never claim statistical correlation proves malicious intent; cite only observed evidence.\n\n"
        f"URL: {url}\nHostname: {hostname}\nOverall Risk Level: {risk_level}\n"
        f"Calibrated ML Phishing Probability: {prob_str}\n"
        f"Heuristic Risk Index: {h_str}\n"
        f"{dims_txt}\n{attr_txt}\n\nObserved Evidence:\n{ind_txt}\n\n"
        "Provide:\n"
        "1. **Assessment Summary** (1-2 concise sentences explaining why the risk level was assigned)\n"
        "2. **Key Contributing Signals** (2-3 factual bullet points)\n"
        "3. **Recommended Action** (1 direct sentence telling the user whether it is safe to browse, login, download, or pay)\n"
        "Keep under 140 words."
    )


def call_groq_ai(prompt: str, api_key: str) -> str:
    """Call Groq OpenAI-compatible Chat Completions endpoint."""
    models = ["openai/gpt-oss-20b", "qwen/qwen3.8-27b"]
    headers = {
        "Authorization": f"Bearer {api_key.strip()}",
        "Content-Type": "application/json",
        "User-Agent": "WebShield-AI/3.0",
    }
    last_error = None
    for model in models:
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": "You provide accurate, evidence-based cybersecurity risk explanations."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 512,
        }
        if "gpt-oss" in model:
            payload["reasoning_effort"] = "low"
        req = urllib.request.Request(
            "https://api.groq.com/openai/v1/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                content = (body.get("choices", [{}])[0].get("message", {}).get("content") or "").strip()
                if content:
                    return content
        except urllib.error.HTTPError as e:
            last_error = f"HTTP {e.code}"
            if e.code in (401, 403):
                raise ValueError("Invalid Groq API key.")
        except Exception as e:
            last_error = str(e)
    raise RuntimeError(f"Groq AI unavailable ({last_error})")


def generate_explanation(
    url: str,
    hostname: str,
    is_phishing: bool,
    risk_level: str,
    phishing_prob: float | None,
    features_dict: dict,
    api_key: str | None = None,
    assessment: dict | None = None,
    attributions: list[dict] | None = None,
    heuristic_risk_index: int | None = None,
) -> dict:
    """Generate human-readable multi-layer explanation with SHAP/feature attributions and Groq fallback."""
    backend_inds = (assessment or {}).get("evidence") or (features_dict.get("_backend_indicators") if isinstance(features_dict, dict) else None)
    indicators = extract_top_indicators(features_dict, is_phishing, risk_level, backend_indicators=backend_inds)
    attr_list = attributions or []

    key = (api_key or os.getenv("GROQ_API_KEY") or DEFAULT_GROQ_KEY or "").strip()
    if key:
        try:
            prompt = build_analysis_prompt(
                url,
                hostname,
                risk_level,
                phishing_prob,
                indicators,
                assessment,
                attr_list,
                heuristic_risk_index=heuristic_risk_index,
            )
            ai_text = call_groq_ai(prompt, key)
            return {
                "explanation": ai_text,
                "top_indicators": indicators,
                "feature_attributions": attr_list,
                "source": "groq",
            }
        except Exception as e:
            logger.warning(f"Groq explanation fallback triggered: {e}")
            err_msg = str(e)
    else:
        err_msg = None

    action = (assessment or {}).get("recommended_action") or (
        "Avoid entering credentials, payment details, or downloading files until verified."
        if risk_level in ("MEDIUM", "HIGH", "CRITICAL", "UNKNOWN")
        else "No suspicious indicators observed across checked dimensions."
    )
    bullets = "\n".join(f"- {ind}" for ind in indicators) if indicators else "- Standard baseline heuristics inspected."
    attr_bullets = ""
    if attr_list:
        attr_bullets = "\n\n**Top Model Feature Attributions:**\n" + "\n".join(
            f"- `{a['feature']}` = `{a['value']}` ({a['direction']}: `{a['risk_contribution']}`)"
            for a in attr_list[:4]
        )

    h_idx = heuristic_risk_index if heuristic_risk_index is not None else (assessment or {}).get("heuristic_risk_index")
    prob_line = f"**Calibrated ML Phishing Probability:** **{phishing_prob * 100:.1f}%**" if phishing_prob is not None else "**Calibrated ML Phishing Probability:** Unavailable"
    heur_line = f"**Heuristic Risk Index:** **{h_idx}/100**" if h_idx is not None else "**Heuristic Risk Index:** Not computed"

    rule_text = (
        f"### Website Safety Assessment ({risk_level} Risk)\n\n"
        f"**Target:** `{hostname or url}`  \n"
        f"{prob_line} | {heur_line} *(heuristics measure observed risk signals separately from ML probabilities)*\n\n"
        f"**Observed Evidence:**\n{bullets}{attr_bullets}\n\n"
        f"**Recommended Action:** {action}"
    )

    return {
        "explanation": rule_text,
        "top_indicators": indicators,
        "feature_attributions": attr_list,
        "source": "rule_based_fallback" if err_msg else "rule_based",
        "error": err_msg,
    }


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    res = generate_explanation(
        url="https://example.com",
        hostname="example.com",
        is_phishing=False,
        risk_level="LOW",
        phishing_prob=0.05,
        features_dict={"IsHTTPS": 1},
        heuristic_risk_index=5,
    )
    print(res["explanation"])
