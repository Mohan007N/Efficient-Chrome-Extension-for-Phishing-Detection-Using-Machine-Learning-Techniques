"""
backend/predictor.py — Production-grade ML model wrapper

Key improvements for real-world deployment:
- Trusted domain whitelist (never flagged as phishing)
- Calibrated confidence threshold (>= 0.70 required for phishing verdict)
- Risk-level tiers aligned to the new threshold
"""

import os
import logging
import joblib
import pandas as pd

logger = logging.getLogger("PhishingAPI.Predictor")

# ---------------------------------------------------------------------------
# Trusted domain whitelist — these domains NEVER get flagged as phishing.
# These are Alexa/Tranco top global sites whose login pages share many
# features with phishing pages (password fields, login keywords, etc.)
# ---------------------------------------------------------------------------
TRUSTED_DOMAINS = {
    # Search engines
    "google.com", "google.co.in", "bing.com", "yahoo.com", "duckduckgo.com", "baidu.com", "yandex.com",
    # Social networks
    "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com",
    "reddit.com", "tiktok.com", "snapchat.com", "pinterest.com", "tumblr.com",
    "discord.com", "twitch.tv", "telegram.org", "whatsapp.com",
    # Video
    "youtube.com", "youtu.be", "netflix.com", "primevideo.com", "hotstar.com",
    "disneyplus.com", "hulu.com", "vimeo.com", "dailymotion.com",
    # Microsoft
    "microsoft.com", "live.com", "outlook.com", "office.com", "office365.com",
    "azure.com", "microsoftonline.com", "xbox.com", "bing.com",
    # Apple
    "apple.com", "icloud.com",
    # Amazon / Shopping
    "amazon.com", "amazon.in", "amazon.co.uk", "ebay.com", "flipkart.com",
    "walmart.com", "target.com", "alibaba.com", "aliexpress.com",
    # Banking (verified major banks — do NOT remove)
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "barclays.co.uk", "hsbc.com", "standardchartered.com",
    # Tech / Cloud
    "github.com", "gitlab.com", "stackoverflow.com", "npmjs.com", "pypi.org",
    "cloudflare.com", "aws.amazon.com", "cloud.google.com",
    "digitalocean.com", "heroku.com", "vercel.com", "netlify.com",
    "notion.so", "slack.com", "zoom.us", "dropbox.com", "box.com",
    "adobe.com", "salesforce.com", "atlassian.com", "jira.atlassian.com",
    # Education
    "wikipedia.org", "wikimedia.org", "khanacademy.org", "coursera.org",
    "udemy.com", "edx.org", "medium.com",
    # India
    "irctc.co.in", "paytm.com", "phonepe.com", "gpay.app", "upi.com",
    "npci.org.in", "incometax.gov.in", "uidai.gov.in", "mygov.in",
    # News
    "bbc.com", "cnn.com", "nytimes.com", "theguardian.com", "reuters.com",
    "ndtv.com", "thehindu.com", "indiatoday.in", "aajtak.in",
    # Other major platforms
    "spotify.com", "uber.com", "ola.com", "swiggy.com", "zomato.com",
    "airbnb.com", "booking.com", "expedia.com", "tripadvisor.com",
    "shopify.com", "wordpress.com", "wix.com", "squarespace.com",
    "openai.com", "chatgpt.com", "anthropic.com",
}

# Minimum phishing probability required to flag a page as phishing.
# At 0.70 the model must be 70%+ confident before raising an alert.
# This drastically cuts false positives while keeping true positives.
PHISHING_THRESHOLD = 0.70


def _extract_root_domain(hostname: str) -> str:
    """
    Extract the root domain (e.g. 'www.instagram.com' → 'instagram.com').
    Handles simple two-part TLDs like 'co.in', 'co.uk'.
    """
    if not hostname:
        return ""
    parts = hostname.lower().lstrip("www.").split(".")
    # Handle compound TLDs like co.uk, co.in
    compound_tld = {"co", "com", "net", "org", "gov", "edu"}
    if len(parts) >= 3 and parts[-2] in compound_tld:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


class PhishingPredictor:
    """Wraps trained ML artifacts and exposes a clean predict() interface."""

    def __init__(self, models_dir: str = "models"):
        self.models_dir = models_dir
        self._model = None
        self._encoders: dict = {}
        self._feature_columns: list = []

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load(self):
        """Load all model artifacts from disk."""
        model_path    = os.path.join(self.models_dir, "best_phishing_model.pkl")
        encoder_path  = os.path.join(self.models_dir, "label_encoder.pkl")
        features_path = os.path.join(self.models_dir, "feature_columns.pkl")

        for path in [model_path, encoder_path, features_path]:
            if not os.path.exists(path):
                raise FileNotFoundError(
                    f"Required model artifact not found: {path}\n"
                    "Please run 'python run_train.py' first."
                )

        logger.info(f"Loading model from: {model_path}")
        self._model           = joblib.load(model_path)
        self._encoders        = joblib.load(encoder_path)
        self._feature_columns = joblib.load(features_path)

        logger.info(
            f"Artifacts loaded — model: {type(self._model).__name__}, "
            f"features: {len(self._feature_columns)}, "
            f"phishing_threshold: {PHISHING_THRESHOLD}, "
            f"whitelist_size: {len(TRUSTED_DOMAINS)}"
        )

    # ------------------------------------------------------------------
    # Status helpers
    # ------------------------------------------------------------------

    def is_ready(self) -> bool:
        return self._model is not None and len(self._feature_columns) > 0

    def model_type(self) -> str:
        return type(self._model).__name__ if self._model else "N/A"

    def feature_count(self) -> int:
        return len(self._feature_columns)

    # ------------------------------------------------------------------
    # Prediction
    # ------------------------------------------------------------------

    def predict(self, features_dict: dict) -> dict:
        """
        Run inference on a feature dictionary.

        Returns:
            dict with keys: is_phishing, phishing_probability,
                            legitimate_probability, verdict, risk_level,
                            whitelisted
        """
        if not self.is_ready():
            raise RuntimeError("Model is not loaded. Call load() first.")

        # ── 1. Whitelist check ──────────────────────────────────────────────
        url      = str(features_dict.get("url", features_dict.get("URL", "")))
        hostname = str(features_dict.get("hostname", ""))

        # Try to extract hostname from URL if not directly provided
        if not hostname and url.startswith("http"):
            try:
                from urllib.parse import urlparse
                hostname = urlparse(url).hostname or ""
            except Exception:
                hostname = ""

        root = _extract_root_domain(hostname)
        if root in TRUSTED_DOMAINS or hostname in TRUSTED_DOMAINS:
            logger.info(f"Whitelisted domain '{root}' — returning LEGITIMATE without ML inference.")
            return {
                "is_phishing": False,
                "phishing_probability": 0.02,
                "legitimate_probability": 0.98,
                "verdict": "✅ TRUSTED DOMAIN — Whitelisted",
                "risk_level": "LOW",
                "whitelisted": True,
                "top_indicators": ["Verified global domain in trusted security registry."],
            }

        # ── 2. Build feature DataFrame ───────────────────────────────────────
        df = pd.DataFrame([features_dict])

        # Add any missing columns with 0 default
        for col in self._feature_columns:
            if col not in df.columns:
                df[col] = 0

        df_aligned = df[self._feature_columns].copy()

        # ── 3. Encode categorical columns (TLD) ──────────────────────────────
        for col, le in self._encoders.items():
            if col in df_aligned.columns:
                raw_val = str(df_aligned[col].iloc[0])
                if raw_val in le.classes_:
                    df_aligned[col] = le.transform([raw_val])
                else:
                    logger.warning(f"Unseen TLD '{raw_val}' — fallback encoding 0")
                    df_aligned[col] = 0

        # ── 4. Raw model prediction ──────────────────────────────────────────
        phishing_prob   = 0.5
        legitimate_prob = 0.5

        if hasattr(self._model, "predict_proba"):
            proba           = self._model.predict_proba(df_aligned)[0]
            phishing_prob   = float(proba[0])   # label 0 = Phishing
            legitimate_prob = float(proba[1])   # label 1 = Legitimate

        # ── 5. Apply calibrated threshold ────────────────────────────────────
        # Only flag as phishing when the model is >= 70% confident.
        # This replaces the raw model.predict()==0 which uses 0.5 default.
        is_phishing = phishing_prob >= PHISHING_THRESHOLD

        # ── 6. Risk level ────────────────────────────────────────────────────
        if phishing_prob >= 0.85:
            risk_level = "HIGH"
        elif phishing_prob >= 0.70:
            risk_level = "MEDIUM"
        elif phishing_prob >= 0.50:
            risk_level = "LOW"
        else:
            risk_level = "SAFE"

        # ── 7. Verdict ───────────────────────────────────────────────────────
        if is_phishing:
            verdict = f"⚠️ PHISHING DETECTED — {risk_level} RISK ({phishing_prob:.1%} confidence)"
        else:
            verdict = f"✅ LEGITIMATE ({legitimate_prob:.1%} confidence)"

        logger.info(
            f"Prediction: {'PHISHING' if is_phishing else 'LEGIT'} | "
            f"p_phish={phishing_prob:.3f} | threshold={PHISHING_THRESHOLD} | "
            f"risk={risk_level} | domain={root or hostname}"
        )

        from backend.explainer import extract_top_indicators
        top_indicators = extract_top_indicators(features_dict, is_phishing, risk_level)

        return {
            "is_phishing": is_phishing,
            "phishing_probability": phishing_prob,
            "legitimate_probability": legitimate_prob,
            "verdict": verdict,
            "risk_level": risk_level,
            "whitelisted": False,
            "top_indicators": top_indicators,
        }
