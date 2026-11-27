"""
backend/predictor.py — Multi-Model Predictor & Hybrid Website Safety Orchestrator

Loads:
- Model 1: Separated URL Risk Classifier (`models/url_model.pkl`)
- Model 2: Separated DOM Behaviour Classifier (`models/dom_model.pkl`)
- Model 3: Brand Impersonation Detector (`src/features.py`)
- Model 4: Credential & Payment Risk Detector (`src/dom_features.py`)
- Model 5: Threat Intelligence Engine (`backend/intel.py`)
- Risk Fusion: HybridRiskEngine (`backend/risk_engine.py`)
"""

from __future__ import annotations

import logging
import os
from typing import Any
from urllib.parse import urlparse

import joblib
import pandas as pd

from backend.intel import UnauthorizedIntelEngine
from backend.risk_engine import HybridRiskEngine
from backend.security import sanitize_telemetry_dict
from src.dom_features import DOM_FEATURE_COLUMNS, extract_dom_features_from_html, normalize_dom_feature_dict
from src.features import URL_FEATURE_COLUMNS, extract_root_domain, extract_url_features
from src.model_registry import get_active_registry_manifest

logger = logging.getLogger("PhishingAPI.Predictor")


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
    """Orchestrates URL ML, DOM ML, Brand/Credential/Payment rules, Threat Intel, and Risk Fusion."""

    def __init__(self, models_dir: str = "models", dataset_dir: str = "dataset"):
        self.models_dir = models_dir
        self.dataset_dir = dataset_dir

        self._url_model = None
        self._url_encoders: dict = {}
        self._url_features: list[str] = list(URL_FEATURE_COLUMNS)

        self._dom_model = None
        self._dom_features: list[str] = list(DOM_FEATURE_COLUMNS)

        self.intel = UnauthorizedIntelEngine(dataset_dir=dataset_dir)
        self.risk_engine = HybridRiskEngine()
        self.manifest: dict = {}

    def load(self):
        """Load versioned URL & DOM models, encoders, and threat intelligence indexes."""
        url_model_path = os.path.join(self.models_dir, "url_model.pkl")
        if not os.path.exists(url_model_path):
            url_model_path = os.path.join(self.models_dir, "best_phishing_model.pkl")
        url_enc_path = os.path.join(self.models_dir, "url_encoders.pkl")
        url_feat_path = os.path.join(self.models_dir, "url_feature_columns.pkl")

        if os.path.exists(url_model_path):
            self._url_model = joblib.load(url_model_path)
        if os.path.exists(url_enc_path):
            self._url_encoders = joblib.load(url_enc_path)
        if os.path.exists(url_feat_path):
            self._url_features = joblib.load(url_feat_path)

        dom_model_path = os.path.join(self.models_dir, "dom_model.pkl")
        dom_feat_path = os.path.join(self.models_dir, "dom_feature_columns.pkl")
        if os.path.exists(dom_model_path):
            self._dom_model = joblib.load(dom_model_path)
        if os.path.exists(dom_feat_path):
            self._dom_features = joblib.load(dom_feat_path)

        self.intel.load()
        self.manifest = get_active_registry_manifest()

        logger.info(
            f"Models loaded — url_model={self.url_model_type()} ({len(self._url_features)} cols), "
            f"dom_model={self.dom_model_type()} ({len(self._dom_features)} cols)"
        )

    def is_ready(self) -> bool:
        return self._url_model is not None or self._dom_model is not None

    def url_model_ready(self) -> bool:
        return self._url_model is not None

    def dom_model_ready(self) -> bool:
        return self._dom_model is not None

    def url_model_type(self) -> str:
        return type(self._url_model).__name__ if self._url_model else "N/A"

    def dom_model_type(self) -> str:
        return type(self._dom_model).__name__ if self._dom_model else "N/A"

    def model_type(self) -> str:
        return f"URL:{self.url_model_type()} + DOM:{self.dom_model_type()}"

    def feature_count(self) -> int:
        return len(self._url_features) + len(self._dom_features)

    def prepare_url_dataframe(self, url: str) -> pd.DataFrame:
        """Build aligned single-row DataFrame for Model 1 (URL Risk Classifier)."""
        feats = extract_url_features(url)
        df = pd.DataFrame([feats])
        for c in self._url_features:
            if c not in df.columns:
                df[c] = 0
        df = df[self._url_features].copy()
        if "tld" in df.columns and "tld" in self._url_encoders:
            df["tld"] = df["tld"].fillna("com").astype(str).str.lower().str.strip()
            df[["tld"]] = self._url_encoders["tld"].transform(df[["tld"]])
        for c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)
        return df

    def prepare_dom_dataframe(self, dom_dict: dict, url: str = "") -> pd.DataFrame:
        """Build aligned single-row DataFrame for Model 2 (DOM Behaviour Classifier)."""
        norm = normalize_dom_feature_dict(dom_dict, url=url)
        df = pd.DataFrame([norm])
        for c in self._dom_features:
            if c not in df.columns:
                df[c] = 0.0
        df = df[self._dom_features].copy()
        for c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)
        return df

    def _predict_url_threat_prob(self, url: str) -> tuple[float | None, pd.DataFrame | None]:
        if self._url_model is None or not url:
            return None, None
        # Ensure we only run URL model when schema matches URL_FEATURE_COLUMNS
        if "url_length" not in self._url_features:
            return None, None
        df_u = self.prepare_url_dataframe(url)
        if hasattr(self._url_model, "predict_proba"):
            proba = self._url_model.predict_proba(df_u)[0]
            # class 0 = risky/phishing, class 1 = benign
            return float(proba[0]), df_u
        pred = int(self._url_model.predict(df_u)[0])
        return (0.85 if pred == 0 else 0.15), df_u

    def _predict_dom_threat_prob(self, dom_dict: dict, url: str = "") -> tuple[float | None, pd.DataFrame | None]:
        if self._dom_model is None:
            return None, None
        df_d = self.prepare_dom_dataframe(dom_dict, url=url)
        if hasattr(self._dom_model, "predict_proba"):
            proba = self._dom_model.predict_proba(df_d)[0]
            return float(proba[0]), df_d
        pred = int(self._dom_model.predict(df_d)[0])
        return (0.85 if pred == 0 else 0.15), df_d

    def assess_website(
        self,
        url: str = "",
        hostname: str = "",
        dom_features: dict | None = None,
        html: str | None = None,
        redirect_chain: list[str] | None = None,
        legacy_payload: dict | None = None,
        deep_scan: bool = True,
    ) -> dict[str, Any]:
        """Full multi-layer website safety and trust assessment."""
        clean_legacy = sanitize_telemetry_dict(legacy_payload or {})
        clean_dom_input = sanitize_telemetry_dict(dom_features or {})

        parsed = urlparse(url or "")
        host = (hostname or parsed.hostname or "").lower().strip()
        root = extract_root_domain(host)
        is_local = _is_local_or_private_host(host)
        is_whitelisted = (not is_local) and self.intel.is_trusted(host)

        # Resolve DOM features cleanly
        has_dom_observation = False
        resolved_dom: dict = {}
        if html and html.strip():
            resolved_dom = extract_dom_features_from_html(url, html)
            has_dom_observation = True
        elif clean_dom_input:
            resolved_dom = normalize_dom_feature_dict(clean_dom_input, url=url)
            has_dom_observation = True
        elif any(k in clean_legacy for k in ("LineOfCode", "HasPasswordField", "NoOfiFrame", "HasExternalFormSubmit")):
            if int(clean_legacy.get("LineOfCode", 0) or 0) > 0 or int(clean_legacy.get("HasTitle", 0) or 0) > 0:
                resolved_dom = normalize_dom_feature_dict(clean_legacy, url=url)
                has_dom_observation = True

        url_threat_prob, url_df = self._predict_url_threat_prob(url) if (url and not is_local) else (None, None)
        dom_threat_prob, dom_df = self._predict_dom_threat_prob(resolved_dom, url=url) if (has_dom_observation and not is_local) else (None, None)

        intel_res = (
            {}
            if is_local
            else self.intel.inspect_domain(
                url,
                host,
                clean_legacy,
                deep_scan=(deep_scan and not is_whitelisted),
                use_ai_audit=False,
            )
        )

        assessment = self.risk_engine.assess(
            url=url,
            hostname=host,
            url_threat_prob=url_threat_prob,
            dom_threat_prob=dom_threat_prob,
            dom_features=resolved_dom,
            intel_result=intel_res,
            redirect_chain=redirect_chain or (intel_res.get("forensics") or {}).get("redirect_chain"),
            is_whitelisted=is_whitelisted,
            is_local=is_local,
            has_dom_observation=has_dom_observation,
        )

        overall = assessment["overall_risk_level"]
        if overall == "CRITICAL":
            verdict = f"🚨 CRITICAL RISK — Threat or strong malicious indicators detected ({root or host})"
        elif overall == "HIGH":
            verdict = f"⚠️ HIGH RISK — Multiple suspicious safety indicators ({root or host})"
        elif overall == "MEDIUM":
            verdict = f"⚡ CAUTION (MEDIUM RISK) — Verify transport/authenticity ({root or host})"
        elif overall == "UNKNOWN":
            verdict = f"❓ UNKNOWN — Insufficient information to assess ({root or host})"
        else:
            verdict = f"✅ LOW RISK — No significant safety indicators detected ({root or host})"

        assessment.update({
            "url": url,
            "hostname": host,
            "verdict": verdict,
            "whitelisted": is_whitelisted,
            "tranco_rank": intel_res.get("tranco_rank"),
            "domain_age_days": (intel_res.get("rdap") or {}).get("domain_age_days"),
            "registry_match": intel_res.get("registry_match") or {},
            "_url_df": url_df,
            "_dom_df": dom_df,
        })
        return assessment

    def predict(self, features_dict: dict, deep_scan: bool = True, use_ai_audit: bool = False) -> dict:
        """
        Backward-compatible prediction interface for Chrome Extension /predict endpoint.
        Includes full multi-dimension `assessment` alongside legacy fields.
        """
        if not self.is_ready():
            raise RuntimeError("No ML models loaded. Run training pipeline first.")

        clean_payload = sanitize_telemetry_dict(features_dict)
        url = str(clean_payload.get("url", clean_payload.get("URL", "")))
        hostname = str(clean_payload.get("hostname", clean_payload.get("Domain", "")))
        if not hostname and url.startswith(("http://", "https://")):
            hostname = urlparse(url).hostname or ""

        assessment = self.assess_website(
            url=url,
            hostname=hostname,
            dom_features=clean_payload.get("dom_features"),
            redirect_chain=clean_payload.get("redirect_chain"),
            legacy_payload=clean_payload,
            deep_scan=deep_scan,
        )

        # Strip internal DataFrames before JSON serialization
        assessment_public = {k: v for k, v in assessment.items() if not k.startswith("_")}
        overall = assessment_public["overall_risk_level"]
        is_risky = overall in ("HIGH", "CRITICAL")
        risk_ratio = round(float(assessment_public["heuristic_risk_index"]) / 100.0, 4)

        return {
            "is_phishing": is_risky,
            "phishing_probability": risk_ratio,
            "legitimate_probability": round(1.0 - risk_ratio, 4),
            "verdict": assessment_public["verdict"],
            "risk_level": overall,
            "whitelisted": assessment_public["whitelisted"],
            "top_indicators": assessment_public["evidence"][:8],
            "assessment": assessment_public,
        }
