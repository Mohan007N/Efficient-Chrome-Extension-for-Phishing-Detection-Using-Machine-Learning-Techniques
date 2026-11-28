"""
backend/predictor.py — Multi-Model Predictor & Hybrid Website Safety Orchestrator (v3.0)

Loads & validates:
- Model 1: Calibrated Separated URL Risk Classifier (`models/url_model.pkl`)
- Model 2: Calibrated Separated DOM Behaviour Classifier (`models/dom_model.pkl`)
- Model 3: Brand Impersonation Detector (`src/features.py`)
- Model 4: Credential & Payment Risk Detector (`src/dom_features.py`)
- Model 5: Threat Intelligence Engine (`backend/intel.py`)
- Optional SSRF-guarded Playwright Inspector (`src/playwright_inspector.py`)
- Risk Fusion: HybridRiskEngine (`backend/risk_engine.py`)

v3.0 Safety Guarantees:
- Explicitly resolves `model.classes_` (`0 = Phishing/Malicious`, `1 = Benign/Legitimate`) and fails
  validation if required class labels are missing.
- Verifies active model SHA-256 checksums against `models/registry/active_manifest.json`.
- Never lets trusted reputation / whitelist skip deep scan or override critical threats.
- Never fabricates ML `phishing_probability` from `heuristic_risk_index / 100`.
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
from backend.security import is_private_or_local_target, sanitize_telemetry_dict
from src.dom_features import DOM_FEATURE_COLUMNS, extract_dom_features_from_html, normalize_dom_feature_dict
from src.evaluate import get_class_probabilities, resolve_class_indices
from src.features import URL_FEATURE_COLUMNS, extract_root_domain, extract_url_features
from src.model_registry import get_active_registry_manifest, verify_active_model_integrity
from src.playwright_inspector import inspect_page_with_playwright

logger = logging.getLogger("PhishingAPI.Predictor")


def _is_local_or_private_host(hostname: str) -> bool:
    """Return True for localhost, loopback, or private LAN hosts."""
    if not hostname:
        return False
    return is_private_or_local_target(f"http://{hostname.strip()}/")


class PhishingPredictor:
    """Orchestrates URL ML, DOM ML, Brand/Credential/Payment rules, Threat Intel, and Risk Fusion."""

    def __init__(self, models_dir: str = "models", dataset_dir: str = "dataset"):
        self.models_dir = models_dir
        self.dataset_dir = dataset_dir

        self._url_model = None
        self._url_encoders: dict = {}
        self._url_features: list[str] = list(URL_FEATURE_COLUMNS)
        self._url_threshold: float = 0.50
        self._url_model_status: str = "not_loaded"

        self._dom_model = None
        self._dom_features: list[str] = list(DOM_FEATURE_COLUMNS)
        self._dom_threshold: float = 0.50
        self._dom_model_status: str = "not_loaded"

        self._model_errors: list[str] = []
        self._integrity_ok: bool = True

        self.intel = UnauthorizedIntelEngine(dataset_dir=dataset_dir)
        self.risk_engine = HybridRiskEngine()
        self.manifest: dict = {}

    def _validate_loaded_model(self, model_obj: Any, role: str) -> bool:
        try:
            resolve_class_indices(model_obj)
            return True
        except Exception as e:
            msg = f"{role} model failed class_mapping validation: {e}"
            logger.error(msg)
            self._model_errors.append(msg)
            return False

    def load(self):
        """Load versioned URL & DOM models, verify registry checksums + classes_, and load threat intel."""
        self._model_errors = []
        self._integrity_ok = True
        self._url_model = None
        self._dom_model = None
        self.manifest = get_active_registry_manifest(models_dir=self.models_dir)

        url_model_path = os.path.join(self.models_dir, "url_model.pkl")
        if not os.path.exists(url_model_path):
            url_model_path = os.path.join(self.models_dir, "best_phishing_model.pkl")
        url_enc_path = os.path.join(self.models_dir, "url_encoders.pkl")
        url_feat_path = os.path.join(self.models_dir, "url_feature_columns.pkl")

        if os.path.exists(url_model_path):
            if "url_risk" in self.manifest.get("models", {}):
                ok_hash, hash_msg = verify_active_model_integrity("url_risk", models_dir=self.models_dir)
                if not ok_hash:
                    self._integrity_ok = False
                    self._url_model_status = "checksum_mismatch"
                    self._model_errors.append(hash_msg)
                else:
                    candidate = joblib.load(url_model_path)
                    if self._validate_loaded_model(candidate, "url_risk"):
                        self._url_model = candidate
                        self._url_model_status = "loaded"
                    else:
                        self._url_model_status = "invalid_classes"
            else:
                candidate = joblib.load(url_model_path)
                if self._validate_loaded_model(candidate, "url_risk"):
                    self._url_model = candidate
                    self._url_model_status = "loaded"
                else:
                    self._url_model_status = "invalid_classes"
        else:
            self._url_model_status = "missing"
            self._model_errors.append(f"Missing URL model file: {url_model_path}")

        if os.path.exists(url_enc_path):
            self._url_encoders = joblib.load(url_enc_path)
        if os.path.exists(url_feat_path):
            self._url_features = joblib.load(url_feat_path)
        self._url_threshold = float(((self.manifest.get("models") or {}).get("url_risk") or {}).get("threshold", 0.50))

        dom_model_path = os.path.join(self.models_dir, "dom_model.pkl")
        dom_feat_path = os.path.join(self.models_dir, "dom_feature_columns.pkl")
        if os.path.exists(dom_model_path):
            if "dom_behavior" in self.manifest.get("models", {}):
                ok_hash, hash_msg = verify_active_model_integrity("dom_behavior", models_dir=self.models_dir)
                if not ok_hash:
                    self._integrity_ok = False
                    self._dom_model_status = "checksum_mismatch"
                    self._model_errors.append(hash_msg)
                else:
                    candidate = joblib.load(dom_model_path)
                    if self._validate_loaded_model(candidate, "dom_behavior"):
                        self._dom_model = candidate
                        self._dom_model_status = "loaded"
                    else:
                        self._dom_model_status = "invalid_classes"
            else:
                candidate = joblib.load(dom_model_path)
                if self._validate_loaded_model(candidate, "dom_behavior"):
                    self._dom_model = candidate
                    self._dom_model_status = "loaded"
                else:
                    self._dom_model_status = "invalid_classes"
        else:
            self._dom_model_status = "missing"
            self._model_errors.append(f"Missing DOM model file: {dom_model_path}")

        if os.path.exists(dom_feat_path):
            self._dom_features = joblib.load(dom_feat_path)
        self._dom_threshold = float(((self.manifest.get("models") or {}).get("dom_behavior") or {}).get("threshold", 0.50))

        self.intel.load()

        logger.info(
            f"Models loaded — url_model={self.url_model_type()} ({self._url_model_status}, {len(self._url_features)} cols), "
            f"dom_model={self.dom_model_type()} ({self._dom_model_status}, {len(self._dom_features)} cols)"
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

    def model_availability_summary(self) -> dict[str, Any]:
        return {
            "url_model": self.url_model_ready(),
            "dom_model": self.dom_model_ready(),
            "url_model_status": self._url_model_status,
            "dom_model_status": self._dom_model_status,
            "url_threshold": self._url_threshold,
            "dom_threshold": self._dom_threshold,
            "integrity_ok": self._integrity_ok,
            "errors": list(self._model_errors),
        }

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
        if "url_length" not in self._url_features:
            return None, None
        df_u = self.prepare_url_dataframe(url)
        prob_phish, _ = get_class_probabilities(self._url_model, df_u)
        return float(prob_phish[0]), df_u

    def _predict_dom_threat_prob(self, dom_dict: dict, url: str = "") -> tuple[float | None, pd.DataFrame | None]:
        if self._dom_model is None:
            return None, None
        df_d = self.prepare_dom_dataframe(dom_dict, url=url)
        prob_phish, _ = get_class_probabilities(self._dom_model, df_d)
        return float(prob_phish[0]), df_d

    def assess_website(
        self,
        url: str = "",
        hostname: str = "",
        dom_features: dict | None = None,
        html: str | None = None,
        redirect_chain: list[str] | None = None,
        legacy_payload: dict | None = None,
        deep_scan: bool = True,
        use_playwright: bool = False,
        reachability: dict | None = None,
    ) -> dict[str, Any]:
        """Full multi-layer website safety and trust assessment."""
        clean_legacy = sanitize_telemetry_dict(legacy_payload or {})
        clean_dom_input = sanitize_telemetry_dict(dom_features or {})

        parsed = urlparse(url or "")
        host = (hostname or parsed.hostname or "").lower().strip()
        root = extract_root_domain(host)
        is_local = _is_local_or_private_host(host)
        is_whitelisted = (not is_local) and self.intel.is_trusted(host)

        has_dom_observation = False
        analysis_mode = "url_only"
        resolved_dom: dict = {}
        pw_redirects: list[str] = []

        if use_playwright and not is_local and not html and not clean_dom_input and url:
            pw_res = inspect_page_with_playwright(url)
            if pw_res.get("ok") and pw_res.get("html"):
                html = pw_res["html"]
                analysis_mode = pw_res.get("analysis_mode", "live_browser_dom")
                pw_redirects = list(pw_res.get("redirect_chain") or [])

        if html and html.strip():
            mode_used = analysis_mode if analysis_mode == "live_browser_dom" else "static_html"
            resolved_dom = extract_dom_features_from_html(url, html, analysis_mode=mode_used)
            analysis_mode = mode_used
            has_dom_observation = True
        elif clean_dom_input:
            analysis_mode = str(clean_dom_input.get("analysis_mode") or "extension_dom")
            resolved_dom = normalize_dom_feature_dict(clean_dom_input, url=url)
            has_dom_observation = True
        elif any(k in clean_legacy for k in ("LineOfCode", "HasPasswordField", "NoOfiFrame", "HasExternalFormSubmit")):
            if int(clean_legacy.get("LineOfCode", 0) or 0) > 0 or int(clean_legacy.get("HasTitle", 0) or 0) > 0:
                analysis_mode = "extension_dom"
                resolved_dom = normalize_dom_feature_dict(clean_legacy, url=url)
                has_dom_observation = True

        url_threat_prob, url_df = self._predict_url_threat_prob(url) if (url and not is_local) else (None, None)
        dom_threat_prob, dom_df = self._predict_dom_threat_prob(resolved_dom, url=url) if (has_dom_observation and not is_local) else (None, None)

        # Trusted domains are NEVER exempt from deep scan
        intel_res = (
            {}
            if is_local
            else self.intel.inspect_domain(
                url,
                host,
                clean_legacy,
                deep_scan=deep_scan,
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
            redirect_chain=redirect_chain or pw_redirects or (intel_res.get("forensics") or {}).get("redirect_chain"),
            is_whitelisted=is_whitelisted,
            is_local=is_local,
            has_dom_observation=has_dom_observation,
            reachability=reachability,
            model_availability=self.model_availability_summary(),
            analysis_mode=analysis_mode,
        )

        overall = assessment["overall_risk_level"]
        if assessment.get("operational_status") == "LOCAL_NETWORK_UNVERIFIED":
            verdict = f"LOCAL NETWORK UNVERIFIED — External safety scan skipped ({root or host})"
        elif overall == "CRITICAL":
            verdict = f"CRITICAL RISK — Threat or strong malicious indicators detected ({root or host})"
        elif overall == "HIGH":
            verdict = f"HIGH RISK — Multiple suspicious safety indicators ({root or host})"
        elif overall == "MEDIUM":
            verdict = f"CAUTION (MEDIUM RISK) — Verify transport/authenticity ({root or host})"
        elif overall == "UNKNOWN":
            verdict = f"UNKNOWN — Insufficient evidence to verify ({root or host})"
        else:
            verdict = f"LOW RISK — No suspicious indicators observed ({root or host})"

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
        Prediction interface returning separated ML `phishing_probability` (or None when unavailable)
        and `heuristic_risk_index`.
        """
        if not self.is_ready():
            raise RuntimeError("No validated ML models loaded. Run training pipeline first.")

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

        assessment_public = {k: v for k, v in assessment.items() if not k.startswith("_")}
        overall = assessment_public["overall_risk_level"]
        is_risky = overall in ("HIGH", "CRITICAL")
        ml_prob = assessment_public.get("phishing_probability")
        legit_prob = round(1.0 - float(ml_prob), 4) if ml_prob is not None else None

        return {
            "is_phishing": is_risky,
            "phishing_probability": ml_prob,
            "legitimate_probability": legit_prob,
            "heuristic_risk_index": assessment_public.get("heuristic_risk_index"),
            "overall_risk_level": overall,
            "confidence": assessment_public.get("confidence", 0.5),
            "operational_status": assessment_public.get("operational_status", "Unknown"),
            "connection_security": assessment_public.get("connection_security", "UNKNOWN"),
            "model_availability": assessment_public.get("model_availability", {}),
            "verdict": assessment_public["verdict"],
            "risk_level": overall,
            "whitelisted": assessment_public["whitelisted"],
            "top_indicators": assessment_public["evidence"][:8],
            "evidence": assessment_public["evidence"],
            "reasoning": assessment_public.get("reasoning", []),
            "assessment": assessment_public,
        }
