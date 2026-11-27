"""
backend/predictor.py — Production ML + Multi-Layer Unauthorized Website Detection Engine

Combines:
1. Trusted domain & local/private host verification
2. Upgraded ML classifier (56 features: 46 base DOM/URL + 10 shared lexical/commerce features)
3. Server-side Unauthorized Website Intelligence Engine (backend/intel.py):
   - Discovered fake-shop, scam & phishing domain index (470k+ domains + verified scam stores)
   - Brand impersonation & typosquatting detection
   - Tranco Top-1M authority check
   - Live RDAP domain age, TLS cert, storefront/payment/refund forensics & Groq AI audit
"""

from __future__ import annotations

import logging
import os
import joblib
import pandas as pd

from backend.intel import UnauthorizedIntelEngine
from src.features import TRUSTED_DOMAINS, engineer_features, extract_root_domain

logger = logging.getLogger("PhishingAPI.Predictor")

# Calibrated probability threshold required to flag a page as unauthorized/phishing.
PHISHING_THRESHOLD = 0.70


def _is_local_or_private_host(hostname: str) -> bool:
    """Return True for localhost, loopback, or private LAN hosts."""
    if not hostname:
        return False
    h = hostname.lower().strip().strip("[]")
    if h in {"localhost", "127.0.0.1", "::1", "0.0.0.0"} or h.endswith(".local"):
        return True
    if h.startswith(("192.168.", "10.")):
        return True
    if h.startswith("172."):
        parts = h.split(".")
        if len(parts) >= 2 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
            return True
    return False


class PhishingPredictor:
    """Wraps trained ML artifacts + UnauthorizedIntelEngine with a unified predict() interface."""

    def __init__(self, models_dir: str = "models", dataset_dir: str = "dataset"):
        self.models_dir = models_dir
        self.dataset_dir = dataset_dir
        self._model = None
        self._encoders: dict = {}
        self._feature_columns: list = []
        self.intel = UnauthorizedIntelEngine(dataset_dir=dataset_dir)

    def load(self):
        """Load ML artifacts and threat/authority intelligence indexes from disk."""
        model_path = os.path.join(self.models_dir, "best_phishing_model.pkl")
        encoder_path = os.path.join(self.models_dir, "label_encoder.pkl")
        features_path = os.path.join(self.models_dir, "feature_columns.pkl")

        for path in [model_path, encoder_path, features_path]:
            if not os.path.exists(path):
                raise FileNotFoundError(
                    f"Required model artifact not found: {path}\n"
                    "Please run 'python src/train.py' first."
                )

        logger.info(f"Loading model from: {model_path}")
        self._model = joblib.load(model_path)
        self._encoders = joblib.load(encoder_path)
        self._feature_columns = joblib.load(features_path)
        self.intel.load()

        logger.info(
            f"Artifacts loaded — model: {type(self._model).__name__}, "
            f"features: {len(self._feature_columns)}, "
            f"phishing_threshold: {PHISHING_THRESHOLD}, "
            f"whitelist_size: {len(TRUSTED_DOMAINS)}"
        )

    def is_ready(self) -> bool:
        return self._model is not None and len(self._feature_columns) > 0

    def model_type(self) -> str:
        return type(self._model).__name__ if self._model else "N/A"

    def feature_count(self) -> int:
        return len(self._feature_columns)

    def _ml_predict_proba(self, features_dict: dict) -> tuple[float, float]:
        """Run the serialized ML model on 56 engineered + base features."""
        df = pd.DataFrame([features_dict])
        eng_df = engineer_features(df)
        for col in eng_df.columns:
            df[col] = eng_df[col].values

        for col in self._feature_columns:
            if col not in df.columns:
                df[col] = 0

        df_aligned = df[self._feature_columns].copy()

        for col, le in self._encoders.items():
            if col in df_aligned.columns:
                raw_val = str(df_aligned[col].iloc[0]).lower().strip().lstrip(".")
                if raw_val in le.classes_:
                    df_aligned[col] = le.transform([raw_val])
                else:
                    fallback_val = int(le.transform(["com"])[0]) if "com" in le.classes_ else 0
                    df_aligned[col] = fallback_val

        if hasattr(self._model, "predict_proba"):
            proba = self._model.predict_proba(df_aligned)[0]
            return float(proba[0]), float(proba[1])
        return 0.5, 0.5

    def predict(self, features_dict: dict, deep_scan: bool = True, use_ai_audit: bool = True) -> dict:
        """
        Run hybrid ML + server-side unauthorized website intelligence prediction.
        Keeps exact PredictionResponse output structure for full Chrome Extension compatibility.
        """
        if not self.is_ready():
            raise RuntimeError("Model is not loaded. Call load() first.")

        url = str(features_dict.get("url", features_dict.get("URL", "")))
        hostname = str(features_dict.get("hostname", features_dict.get("Domain", "")))

        if not hostname and url.startswith("http"):
            try:
                from urllib.parse import urlparse
                hostname = urlparse(url).hostname or ""
            except Exception:
                hostname = ""

        if _is_local_or_private_host(hostname):
            return {
                "is_phishing": False,
                "phishing_probability": 0.01,
                "legitimate_probability": 0.99,
                "verdict": "✅ LOCAL HOST — Safe Development Environment",
                "risk_level": "SAFE",
                "whitelisted": True,
                "top_indicators": ["Local loopback or private network address."],
            }

        root = extract_root_domain(hostname)
        if self.intel.is_trusted(hostname):
            logger.info(f"Whitelisted domain '{root}' — returning LEGITIMATE.")
            return {
                "is_phishing": False,
                "phishing_probability": 0.02,
                "legitimate_probability": 0.98,
                "verdict": "✅ TRUSTED DOMAIN — Whitelisted",
                "risk_level": "LOW",
                "whitelisted": True,
                "top_indicators": ["Verified global/authorized domain in trusted security registry."],
            }

        # ── 1. ML Classifier Score ───────────────────────────────────────────
        ml_phish_prob, _ = self._ml_predict_proba(features_dict)

        # ── 2. Server-Side Intelligence & Forensics ──────────────────────────
        # Always run fast O(1) registry + brand impersonation first; run live RDAP/TLS/HTML
        # forensics when deep_scan is enabled and domain isn't already a confirmed threat feed match.
        fast_intel = self.intel.inspect_domain(url, hostname, features_dict, deep_scan=False, use_ai_audit=False)
        tranco_rank = fast_intel.get("tranco_rank")
        is_established_top_brand = tranco_rank is not None and tranco_rank <= 15_000

        should_deep_probe = (
            deep_scan
            and not fast_intel["registry_match"]["matched"]
            and not is_established_top_brand
            and (
                int(features_dict.get("Pay", 0)) == 1
                or int(features_dict.get("Bank", 0)) == 1
                or int(features_dict.get("Crypto", 0)) == 1
                or int(features_dict.get("HasPasswordField", 0)) == 1
                or ml_phish_prob >= 0.25
                or (url.startswith("http") and (tranco_rank is None or tranco_rank > 25_000))
            )
        )

        intel_res = (
            self.intel.inspect_domain(url, hostname, features_dict, deep_scan=True, use_ai_audit=use_ai_audit)
            if should_deep_probe
            else fast_intel
        )

        backend_risk = float(intel_res.get("backend_risk_score", 0.0))
        backend_indicators = list(intel_res.get("indicators", []))

        # ── 3. Calibrated Probability Fusion ─────────────────────────────────
        if intel_res["registry_match"]["matched"] or intel_res["brand_impersonation_score"] >= 0.80:
            phishing_prob = max(ml_phish_prob, backend_risk)
        elif is_established_top_brand and int(features_dict.get("HasExternalFormSubmit", 0)) == 0:
            # Established Top-15k Tranco sites shouldn't be false-flagged on noisy DOM counts alone
            phishing_prob = min(ml_phish_prob, 0.45)
        elif backend_risk >= 0.55:
            # High forensic/AI/RDAP scam evidence elevates stealthy HTTPS pages that evade DOM counts
            phishing_prob = max(backend_risk, 0.45 * ml_phish_prob + 0.55 * backend_risk)
        elif should_deep_probe and backend_risk <= 0.15 and int(features_dict.get("HasExternalFormSubmit", 0)) == 0:
            # Deep scan verified clean domain age/email/policies -> dampen borderline ML false positives
            forensics = intel_res.get("forensics") or {}
            age_days = (intel_res.get("rdap") or {}).get("domain_age_days")
            has_strong_legit = bool(forensics.get("official_emails")) and (age_days is None or age_days >= 365)
            phishing_prob = min(ml_phish_prob, 0.55) if has_strong_legit else ml_phish_prob
        else:
            phishing_prob = max(ml_phish_prob, 0.35 * ml_phish_prob + 0.65 * backend_risk)

        phishing_prob = round(max(0.0, min(1.0, phishing_prob)), 4)
        legitimate_prob = round(1.0 - phishing_prob, 4)
        is_phishing = phishing_prob >= PHISHING_THRESHOLD

        if phishing_prob >= 0.85:
            risk_level = "HIGH"
        elif phishing_prob >= 0.70:
            risk_level = "MEDIUM"
        elif phishing_prob >= 0.50:
            risk_level = "LOW"
        else:
            risk_level = "SAFE"

        if is_phishing:
            if intel_res["registry_match"]["category"] in ("upfront_payment_scam_store", "fake_shop_or_scam", "scam_commerce_or_clone"):
                verdict = f"⚠️ UNAUTHORIZED / SCAM SITE DETECTED — {risk_level} RISK ({phishing_prob:.1%} confidence)"
            else:
                verdict = f"⚠️ PHISHING / UNAUTHORIZED SITE DETECTED — {risk_level} RISK ({phishing_prob:.1%} confidence)"
        else:
            verdict = f"✅ LEGITIMATE ({legitimate_prob:.1%} confidence)"

        logger.info(
            f"Prediction: {'FLAGGED' if is_phishing else 'LEGIT'} | "
            f"p_final={phishing_prob:.3f} (ml={ml_phish_prob:.3f}, intel={backend_risk:.3f}) | "
            f"risk={risk_level} | domain={root or hostname}"
        )

        from backend.explainer import extract_top_indicators
        top_indicators = extract_top_indicators(
            features_dict,
            is_phishing,
            risk_level,
            backend_indicators=backend_indicators if is_phishing else None,
        )

        return {
            "is_phishing": is_phishing,
            "phishing_probability": phishing_prob,
            "legitimate_probability": legitimate_prob,
            "verdict": verdict,
            "risk_level": risk_level,
            "whitelisted": False,
            "top_indicators": top_indicators,
        }
