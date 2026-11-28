"""
backend/risk_engine.py — Hybrid Multi-Layer Website Safety & Risk Fusion Engine (v3.0)

Combines separated assessments from:
- Model 1: URL Risk Classifier (calibrated ML probability + threshold)
- Model 2: DOM Behaviour Classifier (calibrated ML probability + threshold)
- Model 3: Brand Impersonation Detector
- Model 4: Credential & Payment Risk Detector
- Model 5: Threat Intelligence Engine
- Transport Security (SECURE_HTTPS, HTTPS_MIXED_CONTENT, INSECURE_HTTP, INVALID_CERTIFICATE, UNKNOWN)

v3.0 Security Guarantees:
- Strictly separates ML `phishing_probability` (None when unavailable) from `heuristic_risk_index`.
- Removes whitelist score overrides (`is_whitelisted -> 0.02` eliminated): suspicious DOM, forms,
  external credential harvesting, or threat feeds always elevate risk cleanly even on trusted domains.
- Classifies loopback/private network targets explicitly as `LOCAL_NETWORK_UNVERIFIED` with `UNKNOWN` risk.
- Separates transport security (`INVALID_CERTIFICATE`, `INSECURE_HTTP`) from phishing probability.
- Separates operational states (`Malicious`, `Benign`, `Blocked`, `Unreachable`, `Insufficient evidence`, `Unknown`).
- Distinguishes clearly between "No suspicious evidence observed", "Website not inspected",
  "Model unavailable", "Insufficient evidence", and "Confirmed benign".
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from src.dom_features import evaluate_credential_and_payment_risk, normalize_dom_feature_dict
from src.features import compute_brand_impersonation_details, extract_root_domain


def _score_to_level(score: float | None, has_evidence: bool = True) -> str:
    if score is None or not has_evidence:
        return "UNKNOWN"
    if score >= 0.85:
        return "CRITICAL"
    if score >= 0.65:
        return "HIGH"
    if score >= 0.35:
        return "MEDIUM"
    return "LOW"


class HybridRiskEngine:
    """Fuses ML model probabilities, rule detectors, TLS/reachability, and threat intel."""

    def assess(
        self,
        url: str = "",
        hostname: str = "",
        url_threat_prob: float | None = None,
        dom_threat_prob: float | None = None,
        dom_features: dict | None = None,
        url_features: dict | None = None,
        intel_result: dict | None = None,
        redirect_chain: list[str] | None = None,
        is_whitelisted: bool = False,
        is_local: bool = False,
        has_dom_observation: bool = False,
        reachability: dict | None = None,
        model_availability: dict | None = None,
        analysis_mode: str = "url_only",
    ) -> dict[str, Any]:
        parsed = urlparse(url or "")
        host = (hostname or parsed.hostname or "").lower().strip()
        root = extract_root_domain(host)
        scheme = (parsed.scheme or "").lower()

        dom_norm = normalize_dom_feature_dict(dom_features or {}, url=url)
        is_https = 1 if (scheme == "https" or dom_norm.get("is_https") == 1) else 0
        mixed_content = int(dom_norm.get("mixed_content_count", 0))
        intel = intel_result or {}
        reg = intel.get("registry_match") or {}
        forensics = intel.get("forensics") or {}
        tls_info = intel.get("tls") or {}
        reach = reachability or {}
        avail = model_availability or {
            "url_model": url_threat_prob is not None,
            "dom_model": dom_threat_prob is not None,
        }

        unavailable: list[str] = list(dom_norm.get("unavailable_signals", []))
        if not has_dom_observation and "dom_behavior" not in unavailable:
            unavailable.append("dom_behavior")
        if url_threat_prob is None and "url_ml_model" not in unavailable:
            unavailable.append("url_ml_model")
        if has_dom_observation and dom_threat_prob is None and "dom_ml_model" not in unavailable:
            unavailable.append("dom_ml_model")
        if not intel.get("rdap") or intel.get("rdap", {}).get("domain_age_days") is None:
            if "rdap_domain_age" not in unavailable:
                unavailable.append("rdap_domain_age")

        # ── Local / Private Network Target -> Never claim LOW/safe ───────────
        if is_local:
            return {
                "overall_risk_level": "UNKNOWN",
                "phishing_probability": None,
                "heuristic_risk_index": None,
                "confidence": 0.2,
                "operational_status": "LOCAL_NETWORK_UNVERIFIED",
                "connection_security": "LOCAL_NETWORK_UNVERIFIED",
                "model_availability": avail,
                "analysis_mode": "local_unverified",
                "url_model_threat_probability": None,
                "dom_model_threat_probability": None,
                "dimensions": {
                    "connection_security": {
                        "level": "UNKNOWN",
                        "status": "LOCAL_NETWORK_UNVERIFIED",
                        "evidence": ["Loopback or private RFC1918 address detected; external certificate and threat verification skipped."],
                    },
                    "phishing_risk": {"level": "UNKNOWN", "score": None, "evidence": ["Local target not evaluated by phishing models."]},
                    "malware_risk": {"level": "UNKNOWN", "score": None, "evidence": ["Local target not scanned externally."]},
                    "credential_risk": {"level": "UNKNOWN", "score": None, "evidence": []},
                    "payment_risk": {"level": "UNKNOWN", "score": None, "evidence": []},
                    "deceptive_behavior_risk": {"level": "UNKNOWN", "score": None, "evidence": []},
                },
                "brand_impersonation": {"brand_similarity_score": 0.0, "matched_brand": None, "evidence": []},
                "evidence": [
                    "Website not inspected: Target resolves to a loopback or private local network address (LOCAL_NETWORK_UNVERIFIED)."
                ],
                "reasoning": [
                    "Private/local network targets cannot be verified via public threat intelligence or external scanning.",
                    "Status is set to UNKNOWN (LOCAL_NETWORK_UNVERIFIED) rather than assuming safety.",
                ],
                "unavailable_signals": unavailable,
                "recommended_action": "Local or private network resource. Only proceed if you intentionally host or trust this local service.",
                "assessment_confidence_note": "Website not inspected by external ML or threat feeds (LOCAL_NETWORK_UNVERIFIED).",
            }

        # ── 1. Connection Security (Strictly separated from phishing ML probability)
        conn_evidence: list[str] = []
        ssl_error = bool(tls_info.get("ssl_error") or reach.get("ssl_error"))
        if ssl_error:
            conn_level = "HIGH"
            conn_status = "INVALID_CERTIFICATE"
            detail = tls_info.get("ssl_error_detail") or reach.get("network_error") or "Certificate validation failed."
            conn_evidence.append(f"Invalid or untrusted TLS certificate ({detail}).")
        elif is_https == 1 and mixed_content == 0:
            conn_level = "LOW"
            conn_status = "SECURE_HTTPS"
            conn_evidence.append("Page served over encrypted HTTPS connection.")
        elif is_https == 1 and mixed_content > 0:
            conn_level = "MEDIUM"
            conn_status = "HTTPS_MIXED_CONTENT"
            conn_evidence.append(f"HTTPS page loads {mixed_content} insecure HTTP subresource(s).")
        elif scheme == "http" or is_https == 0:
            conn_level = "MEDIUM"
            conn_status = "INSECURE_HTTP"
            conn_evidence.append("Insecure HTTP transport (unencrypted connection; avoid entering sensitive credentials or payments).")
        else:
            conn_level = "UNKNOWN"
            conn_status = "UNKNOWN"
            conn_evidence.append("Transport protocol could not be confirmed.")

        # ── 2. Model 3: Brand Impersonation ──────────────────────────────────
        brand_info = compute_brand_impersonation_details(host, str(forensics.get("title", "")))
        brand_score = float(brand_info["brand_similarity_score"])

        # ── 3. Model 4: Credential & Payment Risk ────────────────────────────
        cred_pay = evaluate_credential_and_payment_risk(url, dom_norm, brand_info)
        cred_score = float(cred_pay["credential_risk_score"])
        cred_evidence = list(cred_pay["credential_evidence"])
        pay_score = float(cred_pay["payment_risk_score"])
        pay_evidence = list(cred_pay["payment_evidence"])

        if forensics.get("is_commerce_or_portal") and float(forensics.get("forensic_risk_score", 0.0)) > 0:
            f_risk = float(forensics.get("forensic_risk_score", 0.0))
            pay_score = max(pay_score, min(1.0, f_risk))
            for fl in forensics.get("forensic_flags", []):
                if fl not in pay_evidence:
                    pay_evidence.append(fl)

        # ── 4. Calibrated ML Phishing Probability vs Heuristic Phishing Risk ─
        ml_components: list[tuple[float, float]] = []
        if url_threat_prob is not None:
            ml_components.append((0.45 if dom_threat_prob is not None else 1.0, float(url_threat_prob)))
        if dom_threat_prob is not None:
            ml_components.append((0.55 if url_threat_prob is not None else 1.0, float(dom_threat_prob)))

        if ml_components:
            w_sum = sum(w for w, _ in ml_components)
            ml_phishing_prob: float | None = round(sum(w * p for w, p in ml_components) / max(w_sum, 1e-9), 4)
        else:
            ml_phishing_prob = None

        phish_evidence: list[str] = []
        phish_signals: list[float] = []
        if url_threat_prob is not None:
            phish_signals.append(float(url_threat_prob))
            if float(url_threat_prob) >= 0.65:
                phish_evidence.append(f"URL ML classifier flagged lexical/domain anomalies (model prob={float(url_threat_prob):.2f}).")
        if dom_threat_prob is not None:
            phish_signals.append(float(dom_threat_prob))
            if float(dom_threat_prob) >= 0.65:
                phish_evidence.append(f"DOM behaviour ML classifier flagged structural/form anomalies (model prob={float(dom_threat_prob):.2f}).")
        if brand_score >= 0.80:
            phish_signals.append(brand_score)
            phish_evidence.extend(brand_info["evidence"])

        reg_matched = bool(reg.get("matched"))
        reg_cat = str(reg.get("category") or "")
        reg_source = str(reg.get("source") or "")
        if reg_matched:
            if "malware" in reg_cat or reg_source == "urlhaus":
                pass
            elif "payment" in reg_cat or "fake_shop" in reg_cat or "scam" in reg_cat:
                pay_score = max(pay_score, float(reg.get("risk_floor", 0.90)))
                pay_evidence.insert(0, f"Threat Intelligence ({reg_source}): {reg.get('reason')}")
            else:
                phish_signals.append(float(reg.get("risk_floor", 0.92)))
                phish_evidence.insert(0, f"Threat Intelligence ({reg_source}): {reg.get('reason')}")

        if phish_signals:
            phish_score: float | None = max(phish_signals) if reg_matched else sum(phish_signals) / len(phish_signals)
            if url_threat_prob is not None and dom_threat_prob is not None:
                if url_threat_prob >= 0.60 and dom_threat_prob >= 0.60:
                    phish_score = max(phish_score, 0.82)
        else:
            phish_score = None

        # ── 5. Malware Risk ──────────────────────────────────────────────────
        malware_evidence: list[str] = []
        malware_score = 0.0
        if reg_matched and ("malware" in reg_cat or reg_source in ("urlhaus", "hagezi_tif")):
            malware_score = max(malware_score, float(reg.get("risk_floor", 0.90)))
            malware_evidence.append(f"Malware Threat Feed ({reg_source}): {reg.get('reason')}")

        fake_dl = int(dom_norm.get("fake_download_button_count", 0))
        susp_js = int(dom_norm.get("suspicious_inline_js_count", 0))
        obf_js = float(dom_norm.get("obfuscated_js_score", 0.0))
        dyn_mut = int(dom_norm.get("dynamic_dom_mutation_count", 0))

        if fake_dl > 0:
            malware_score += min(0.50, 0.35 + 0.10 * (fake_dl - 1))
            malware_evidence.append(f"Detected {fake_dl} deceptive or executable download button/link pattern(s).")
        if susp_js >= 2 and (obf_js >= 0.50 or dyn_mut > 0):
            malware_score += 0.45
            malware_evidence.append("Suspicious obfuscated inline JavaScript combined with dynamic script/iframe injection.")
        elif obf_js >= 0.70:
            malware_score += 0.30
            malware_evidence.append("High-entropy obfuscated inline JavaScript detected.")
        malware_score = round(min(1.0, malware_score), 4)

        # ── 6. Deceptive Behaviour Risk ──────────────────────────────────────
        dec_evidence: list[str] = []
        dec_score = 0.0
        hidden_ifr = int(dom_norm.get("num_hidden_iframes", 0))
        popups = int(dom_norm.get("popup_trigger_count", 0))
        meta_redir = int(dom_norm.get("meta_refresh_redirects", 0))
        js_redir = int(dom_norm.get("js_redirect_indicators", 0))
        mislead_cta = int(dom_norm.get("misleading_button_count", 0))
        notif_prompt = int(dom_norm.get("notification_prompt_requested", 0))
        susp_link_ratio = float(dom_norm.get("suspicious_link_ratio", 0.0))

        ext_redirects = max(0, len(redirect_chain or []) - 1)
        if hidden_ifr > 0:
            dec_score += 0.35
            dec_evidence.append(f"Detected {hidden_ifr} hidden or zero-dimension iframe(s).")
        if meta_redir > 0 or js_redir > 0 or ext_redirects >= 2:
            dec_score += 0.35
            dec_evidence.append("Multiple or automatic page redirect indicators observed.")
        if popups >= 2:
            dec_score += 0.25
            dec_evidence.append(f"Observed {popups} window.open popup trigger(s).")
        if notif_prompt:
            dec_score += 0.20
            dec_evidence.append("Page requests browser notification permissions.")
        if mislead_cta >= 2:
            dec_score += 0.25
            dec_evidence.append("Urgency or deceptive call-to-action phrasing detected.")
        if susp_link_ratio >= 0.40 and int(dom_norm.get("html_line_count", 0)) > 20:
            dec_score += 0.20
            dec_evidence.append(f"High proportion of dummy/javascript links ({susp_link_ratio:.0%}).")
        dec_score = round(min(1.0, dec_score), 4)

        # ── 7. Operational Reachability & Firewall Checks ────────────────────
        is_blocked_fw = bool(reach.get("dns_sinkholed") or reach.get("firewall_block_page"))
        is_unreachable = bool(reach.get("connection_blocked") and not is_blocked_fw)
        if is_blocked_fw:
            dec_evidence.append("Network firewall/DNS sinkhole blocked access to destination (not proof of ML phishing).")

        # ── 8. Dimension Levels & Overall Risk Assessment ────────────────────
        phish_level = _score_to_level(phish_score, has_evidence=(phish_score is not None))
        malware_level = _score_to_level(malware_score, has_evidence=(has_dom_observation or reg_matched))
        cred_level = _score_to_level(cred_score, has_evidence=has_dom_observation or bool(cred_evidence))
        pay_level = _score_to_level(pay_score, has_evidence=has_dom_observation or bool(pay_evidence))
        dec_level = _score_to_level(dec_score, has_evidence=has_dom_observation or ext_redirects > 0)

        threat_dims = [phish_level, malware_level, cred_level, pay_level, dec_level]
        num_elevated = sum(1 for lv in threat_dims if lv in ("MEDIUM", "HIGH", "CRITICAL"))

        if reg_matched and float(reg.get("risk_floor", 0.0)) >= 0.90:
            overall = "CRITICAL"
        elif "CRITICAL" in threat_dims:
            overall = "CRITICAL"
        elif "HIGH" in threat_dims or conn_level == "HIGH" or num_elevated >= 2:
            overall = "HIGH"
        elif "MEDIUM" in threat_dims or conn_level == "MEDIUM":
            overall = "MEDIUM"
        elif (
            (phish_score is None and not has_dom_observation)
            or (is_blocked_fw and not reg_matched and phish_level == "UNKNOWN")
            or (is_unreachable and not reg_matched and phish_level == "UNKNOWN")
        ):
            overall = "UNKNOWN"
        else:
            overall = "LOW"

        # Separate Heuristic Risk Index (0..100) from calibrated ML phishing_probability
        numeric_subs = [
            x for x in (phish_score, malware_score, cred_score, pay_score, dec_score)
            if x is not None
        ]
        if conn_status == "INVALID_CERTIFICATE":
            numeric_subs.append(0.70)
        max_sub = max(numeric_subs) if numeric_subs else 0.0
        mean_top2 = sum(sorted(numeric_subs, reverse=True)[:2]) / max(1, min(2, len(numeric_subs))) if numeric_subs else 0.0
        heuristic_index = int(round(min(100.0, max(max_sub, 0.7 * max_sub + 0.3 * mean_top2) * 100.0)))
        if overall == "MEDIUM" and conn_level == "MEDIUM" and heuristic_index < 35:
            heuristic_index = 35
        if overall == "HIGH" and conn_level == "HIGH" and heuristic_index < 65:
            heuristic_index = 65

        # Operational status & confidence (clearly separating evidence levels)
        if overall in ("HIGH", "CRITICAL") and (
            reg_matched or phish_level in ("HIGH", "CRITICAL") or malware_level in ("HIGH", "CRITICAL")
            or cred_level in ("HIGH", "CRITICAL") or pay_level in ("HIGH", "CRITICAL")
        ):
            operational_status = "Malicious"
        elif is_blocked_fw:
            operational_status = "Blocked"
        elif is_unreachable:
            operational_status = "Unreachable"
        elif overall == "UNKNOWN" or (not has_dom_observation and not reg_matched and ml_phishing_prob is None):
            operational_status = "Insufficient evidence"
        elif overall in ("LOW", "MEDIUM") and has_dom_observation and ml_phishing_prob is not None:
            operational_status = "Benign"
        else:
            operational_status = "Insufficient evidence" if overall == "UNKNOWN" else "Benign"

        conf = 0.35
        if ml_phishing_prob is not None:
            conf += 0.25
        if has_dom_observation:
            conf += 0.25
        if reg_matched or is_whitelisted:
            conf += 0.10
        if conn_status in ("INVALID_CERTIFICATE",):
            conf = max(conf, 0.80)
        if operational_status in ("Blocked", "Unreachable", "Insufficient evidence"):
            conf = min(conf, 0.55)
        conf = round(min(0.99, conf), 3)

        all_evidence: list[str] = []
        for ev_list in (phish_evidence, malware_evidence, cred_evidence, pay_evidence, dec_evidence, conn_evidence):
            for item in ev_list:
                if item not in all_evidence:
                    all_evidence.append(item)

        if is_whitelisted and not reg_matched and cred_score < 0.35 and pay_score < 0.35 and phish_level in ("LOW", "UNKNOWN"):
            note = "Established domain present on reference reputation allowlist; DOM/heuristic scans were NOT bypassed."
            if note not in all_evidence:
                all_evidence.append(note)

        reasoning: list[str] = []
        if operational_status == "Malicious":
            reasoning.append("Strong malicious or high-risk behavioural/intelligence indicators observed.")
        elif operational_status == "Blocked":
            reasoning.append("Target appears blocked by DNS sinkhole or firewall policy rather than verified safe.")
        elif operational_status == "Unreachable":
            reasoning.append("Host unreachable or timed out; structural inspection could not be completed.")
        elif operational_status == "Insufficient evidence":
            if ml_phishing_prob is None:
                reasoning.append("Model unavailable or DOM not observed — insufficient evidence to confirm benign status.")
            else:
                reasoning.append("Insufficient evidence: live DOM inspection not available.")
        elif is_whitelisted and has_dom_observation:
            reasoning.append("Confirmed benign: reference reputation and live URL/DOM inspection showed no suspicious indicators.")
        else:
            reasoning.append("No suspicious evidence observed across evaluated URL and DOM layers.")

        if overall == "CRITICAL":
            action = "Do not enter credentials, download files, or make payments. Leave this website immediately."
        elif overall == "HIGH":
            action = "Avoid entering passwords, personal details, or payment information until independently verified."
        elif overall == "MEDIUM":
            action = "Proceed with caution. Verify domain authenticity and avoid sensitive transactions if unencrypted."
        elif overall == "UNKNOWN":
            action = "Insufficient structural or domain evidence to verify safety. Exercise caution before sharing data."
        else:
            action = "No suspicious evidence observed across inspected URL, DOM, and reputation checks."

        return {
            "overall_risk_level": overall,
            "phishing_probability": ml_phishing_prob,
            "heuristic_risk_index": heuristic_index,
            "confidence": conf,
            "operational_status": operational_status,
            "connection_security": conn_status,
            "model_availability": avail,
            "analysis_mode": analysis_mode,
            "url_model_threat_probability": round(float(url_threat_prob), 4) if url_threat_prob is not None else None,
            "dom_model_threat_probability": round(float(dom_threat_prob), 4) if dom_threat_prob is not None else None,
            "dimensions": {
                "connection_security": {"level": conn_level, "status": conn_status, "evidence": conn_evidence},
                "phishing_risk": {"level": phish_level, "score": round(phish_score, 4) if phish_score is not None else None, "evidence": phish_evidence},
                "malware_risk": {"level": malware_level, "score": malware_score, "evidence": malware_evidence},
                "credential_risk": {"level": cred_level, "score": cred_score, "evidence": cred_evidence},
                "payment_risk": {"level": pay_level, "score": pay_score, "evidence": pay_evidence},
                "deceptive_behavior_risk": {"level": dec_level, "score": dec_score, "evidence": dec_evidence},
            },
            "brand_impersonation": brand_info,
            "evidence": all_evidence,
            "reasoning": reasoning,
            "unavailable_signals": unavailable,
            "recommended_action": action,
            "assessment_confidence_note": (
                f"operational_status={operational_status}; phishing_probability={'null (model unavailable)' if ml_phishing_prob is None else ml_phishing_prob}; "
                f"heuristic_risk_index={heuristic_index}/100 (distinct from ML probability)."
            ),
        }
