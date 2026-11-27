"""
backend/intel.py — Server-Side Unauthorized Website Intelligence & Forensics Engine

Combines:
1. Fast O(1) lookup against discovered unauthorized/fake-shop/scam registries
   (verified non-delivery registry, HaGeZi Fake, OpenPhish, Scam-Blocklist)
2. Tranco Top-1M authority lookup
3. Brand impersonation & typosquatting detection
4. Cached live server-side verification (RDAP domain age, TLS cert check,
   storefront/payment/refund/contact forensics, and Groq AI merchant audit)
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import gzip
import json
import logging
import os
import re
import time
import urllib.request
from urllib.parse import urlparse

import pandas as pd
from dotenv import load_dotenv

from src.features import (
    TRUSTED_DOMAINS,
    detect_brand_impersonation,
    extract_root_domain,
)
from src.web_forensics import (
    analyze_storefront_forensics,
    fetch_url_html,
    inspect_rdap_domain,
    inspect_tls_certificate,
)

load_dotenv(override=True)

logger = logging.getLogger("PhishingAPI.Intel")


class UnauthorizedIntelEngine:
    """Thread-safe in-memory threat intelligence & live storefront forensics engine."""

    def __init__(self, dataset_dir: str = "dataset", cache_ttl_seconds: int = 3600):
        self.dataset_dir = dataset_dir
        self.cache_ttl_seconds = cache_ttl_seconds

        self.verified_sites: dict[str, dict] = {
            "vlebazaar.in": {
                "url": "https://vlebazaar.in/",
                "category": "upfront_payment_scam_store",
                "source": "verified_consumer_fraud_registry",
                "reason": "High-volume non-delivery & prepaid order scam reports; missing GSTIN/official email, store-credit refund trap, WhatsApp-only support.",
            }
        }
        self.hagezi_fake: set[str] = set()
        self.openphish_domains: set[str] = set()
        self.jarelllama_scams: set[str] = set()
        self.tranco_ranks: dict[str, int] = {}

        self._live_cache: dict[str, tuple[float, dict]] = {}
        self.loaded = False

    def load(self):
        """Load compressed unauthorized domain indexes and Tranco rankings into memory."""
        idx_path = os.path.join(self.dataset_dir, "unauthorized_domains.json.gz")
        if os.path.exists(idx_path):
            try:
                t0 = time.time()
                with gzip.open(idx_path, "rt", encoding="utf-8") as gz:
                    data = json.load(gz)
                self.verified_sites.update(data.get("verified", {}))
                self.hagezi_fake = set(data.get("hagezi_fake", []))
                self.openphish_domains = set(data.get("openphish_domains", []))
                self.jarelllama_scams = set(data.get("jarelllama_scams", []))
                logger.info(
                    f"Loaded unauthorized domain index in {time.time() - t0:.2f}s: "
                    f"verified={len(self.verified_sites)}, hagezi_fake={len(self.hagezi_fake):,}, "
                    f"openphish={len(self.openphish_domains):,}, scam_blocklist={len(self.jarelllama_scams):,}"
                )
            except Exception as e:
                logger.warning(f"Failed loading {idx_path}: {e}")
        else:
            logger.warning(f"Unauthorized index not found at {idx_path}. Run src/discover_unauthorized_sites.py.")

        tranco_path = os.path.join(self.dataset_dir, "tranco_top1m.json.gz")
        if os.path.exists(tranco_path):
            try:
                t0 = time.time()
                with gzip.open(tranco_path, "rt", encoding="utf-8") as gz:
                    self.tranco_ranks = json.load(gz)
                logger.info(f"Loaded {len(self.tranco_ranks):,} Tranco ranks in {time.time() - t0:.2f}s.")
            except Exception as e:
                logger.warning(f"Failed loading {tranco_path}: {e}")

        self.loaded = True

    def is_trusted(self, hostname: str) -> bool:
        h = (hostname or "").lower().strip().rstrip(".")
        if ":" in h:
            h = h.split(":", 1)[0]
        root = extract_root_domain(h)
        return h in TRUSTED_DOMAINS or root in TRUSTED_DOMAINS

    def get_tranco_rank(self, hostname: str) -> int | None:
        h = (hostname or "").lower().strip().rstrip(".")
        if ":" in h:
            h = h.split(":", 1)[0]
        root = extract_root_domain(h)
        return self.tranco_ranks.get(h) or self.tranco_ranks.get(root)

    def lookup_registry(self, hostname: str) -> dict:
        """Check exact host and root domain against discovered unauthorized/scam registries."""
        h = (hostname or "").lower().strip().rstrip(".")
        if ":" in h:
            h = h.split(":", 1)[0]
        root = extract_root_domain(h)

        for candidate in (h, root):
            if not candidate:
                continue
            if candidate in self.verified_sites:
                meta = self.verified_sites[candidate]
                return {
                    "matched": True,
                    "source": meta.get("source", "verified_consumer_fraud_registry"),
                    "category": meta.get("category", "upfront_payment_scam_store"),
                    "reason": meta.get("reason", "Confirmed unauthorized/scam website."),
                    "risk_floor": 0.96,
                }
            if candidate in self.hagezi_fake:
                return {
                    "matched": True,
                    "source": "hagezi_fake",
                    "category": "fake_shop_or_scam",
                    "reason": f"Domain '{candidate}' is flagged in the HaGeZi Fake/Scam Storefront intelligence feed.",
                    "risk_floor": 0.92,
                }
            if candidate in self.openphish_domains:
                return {
                    "matched": True,
                    "source": "openphish",
                    "category": "active_phish_portal",
                    "reason": f"Domain '{candidate}' is actively listed in the OpenPhish threat feed.",
                    "risk_floor": 0.94,
                }
            if candidate in self.jarelllama_scams:
                return {
                    "matched": True,
                    "source": "jarelllama_scams",
                    "category": "scam_blocklist",
                    "reason": f"Domain '{candidate}' is listed in the Scam-Blocklist threat intelligence feed.",
                    "risk_floor": 0.88,
                }

        return {"matched": False, "source": None, "category": None, "reason": None, "risk_floor": 0.0}

    def _audit_with_groq(self, url: str, hostname: str, evidence: dict) -> dict | None:
        """Run a concise Groq AI legitimacy & scam audit when a commerce/portal site shows red flags."""
        api_key = (os.getenv("GROQ_API_KEY") or "").strip()
        if not api_key:
            return None

        prompt = (
            "You are a Cybersecurity & Consumer Fraud Analyst evaluating whether a website is an "
            "UNAUTHORIZED / UPFRONT-PAYMENT SCAM (fake shopping store, non-delivery site like vlebazaar, "
            "fake booking/service portal, or brand clone) vs a genuine legitimate business.\n\n"
            f"URL: {url}\n"
            f"Hostname: {hostname}\n"
            f"Tranco Top-1M Rank: {evidence.get('tranco_rank')}\n"
            f"Domain Created Date: {evidence.get('created_date')} (Age days: {evidence.get('domain_age_days')})\n"
            f"TLS Subject Org: {evidence.get('subject_org')} | Issuer: {evidence.get('issuer_org')}\n"
            f"Brand Impersonation Match: {evidence.get('matched_brand')}\n"
            f"Official Domain Emails Found: {evidence.get('official_emails')}\n"
            f"Free Webmail Emails Found: {evidence.get('free_emails')}\n"
            f"Corporate ID (GSTIN/CIN/VAT) Found: {evidence.get('has_corp_id')}\n"
            f"Accepts Prepaid/UPI: {evidence.get('has_prepaid')} | Cash on Delivery Found: {evidence.get('has_cod')}\n"
            f"Restrictive Refund Clauses: {evidence.get('restrictive_refund_clauses')}\n"
            f"Forensic Flags: {evidence.get('forensic_flags')}\n"
            f"Page Excerpt: {evidence.get('text_excerpt', '')[:650]}\n\n"
            'Respond ONLY in valid JSON: {"verdict": "SCAM_OR_UNAUTHORIZED" | "SUSPICIOUS" | "LEGITIMATE", '
            '"scam_risk": <float 0.0 to 1.0>, "reason": "<one concise factual sentence>"}'
        )

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "PhishGuard-Intel/1.0",
        }
        for model in ("openai/gpt-oss-20b", "qwen/qwen3.8-27b"):
            payload = {
                "model": model,
                "messages": [
                    {"role": "system", "content": "Respond strictly with valid JSON matching the requested schema."},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.1,
                "max_tokens": 250,
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
                with urllib.request.urlopen(req, timeout=6.0) as resp:
                    body = json.loads(resp.read().decode("utf-8"))
                raw_txt = (body.get("choices", [{}])[0].get("message", {}).get("content") or "").strip()
                m = re.search(r"\{.*\}", raw_txt, re.S)
                if m:
                    parsed = json.loads(m.group(0))
                    return {
                        "verdict": str(parsed.get("verdict", "SUSPICIOUS")),
                        "scam_risk": float(parsed.get("scam_risk", 0.5)),
                        "reason": str(parsed.get("reason", "")).strip(),
                    }
            except Exception as e:
                logger.debug(f"Groq merchant audit ({model}) skipped: {e}")
                continue
        return None

    def inspect_domain(
        self,
        url: str,
        hostname: str,
        features_dict: dict | None = None,
        deep_scan: bool = True,
        use_ai_audit: bool = True,
    ) -> dict:
        """
        Run full multi-layer backend verification for an arbitrary URL/hostname.
        Uses TTL caching so repeat lookups on the same domain are instant.
        """
        parsed = urlparse(url) if url else None
        host = (hostname or (parsed.hostname if parsed else "") or "").lower().strip().rstrip(".")
        if ":" in host:
            host = host.split(":", 1)[0]
        root = extract_root_domain(host)

        reg = self.lookup_registry(host)
        tranco_rank = self.get_tranco_rank(host)
        imp_score, matched_brand = detect_brand_impersonation(host)

        result = {
            "hostname": host,
            "root_domain": root,
            "tranco_rank": tranco_rank,
            "registry_match": reg,
            "brand_impersonation_score": imp_score,
            "matched_brand": matched_brand,
            "rdap": {},
            "tls": {},
            "forensics": {},
            "ai_audit": None,
            "backend_risk_score": reg["risk_floor"] if reg["matched"] else 0.0,
            "indicators": [],
        }

        if reg["matched"] and reg["reason"]:
            result["indicators"].append(f"Threat Intelligence Match ({reg['source']}): {reg['reason']}")

        if imp_score >= 0.80 and matched_brand:
            result["backend_risk_score"] = max(result["backend_risk_score"], 0.88)
            result["indicators"].append(
                f"Brand Impersonation: Unauthorized domain '{root}' mimics trusted brand '{matched_brand}'."
            )

        if not deep_scan or not host or "." not in host:
            return result

        # Check cache for live RDAP/TLS/storefront checks
        now = time.time()
        cache_key = root or host
        cached = self._live_cache.get(cache_key)
        if cached and (now - cached[0]) < self.cache_ttl_seconds:
            live_data = cached[1]
        else:
            target_url = url if (url and url.startswith("http")) else f"https://{host}/"
            with ThreadPoolExecutor(max_workers=3) as pool:
                fut_rdap = pool.submit(inspect_rdap_domain, host, 2.5)
                fut_tls = pool.submit(inspect_tls_certificate, host, 2.5)
                fut_html = pool.submit(self._fetch_and_forensics, target_url)
                rdap_info = fut_rdap.result()
                tls_info = fut_tls.result()
                forensics_info = fut_html.result()

            live_data = {
                "rdap": rdap_info,
                "tls": tls_info,
                "forensics": forensics_info,
            }
            self._live_cache[cache_key] = (now, live_data)

        rdap_info = live_data["rdap"]
        tls_info = live_data["tls"]
        forensics = live_data["forensics"]
        result["rdap"] = rdap_info
        result["tls"] = tls_info
        result["forensics"] = forensics

        flags = list(forensics.get("forensic_flags", []))
        score = float(forensics.get("forensic_risk_score", 0.0))

        # Combine RDAP domain age & TLS signals
        age_days = rdap_info.get("domain_age_days")
        span_days = rdap_info.get("registration_span_days")
        f_pay = int((features_dict or {}).get("Pay", 0)) == 1
        f_bank = int((features_dict or {}).get("Bank", 0)) == 1
        f_pwd = int((features_dict or {}).get("HasPasswordField", 0)) == 1
        is_commerce = bool(forensics.get("is_commerce_or_portal")) or f_pay or f_bank

        if age_days is not None:
            if age_days < 90:
                score += 0.38
                flags.append(f"Newly Registered Domain: Created {age_days} days ago ({rdap_info.get('created_date')}) — high risk for disposable scam sites.")
            elif age_days < 270 and (is_commerce or f_pwd):
                score += 0.22
                flags.append(f"Young Domain Age: Payment/login site domain is only {age_days} days old.")

        if span_days is not None and span_days <= 370 and is_commerce and not forensics.get("has_corp_id"):
            score += 0.08

        if tls_info.get("is_dv_short_lived") and is_commerce and not forensics.get("has_corp_id"):
            score += 0.08

        # Popularity context (remember: unranked or low-rank is only a modifier alongside commerce red flags)
        if tranco_rank is None and (is_commerce or f_pwd):
            score += 0.10
            flags.append("No Established Web Authority: Site is unranked in Tranco Top-1M global registry.")
        elif tranco_rank is not None and tranco_rank > 100_000 and score >= 0.28:
            score += 0.08

        score = min(1.0, score)

        # Optional Groq AI Merchant & Fraud Audit when suspicious commerce/portal signals cluster
        ai_audit = live_data.get("ai_audit")
        if (
            use_ai_audit
            and ai_audit is None
            and not reg["matched"]
            and (is_commerce or f_pwd)
            and (tranco_rank is None or tranco_rank > 25_000)
            and score >= 0.30
        ):
            evidence = {
                "tranco_rank": tranco_rank,
                "created_date": rdap_info.get("created_date"),
                "domain_age_days": age_days,
                "subject_org": tls_info.get("subject_org"),
                "issuer_org": tls_info.get("issuer_org"),
                "matched_brand": matched_brand,
                "official_emails": forensics.get("official_emails", []),
                "free_emails": forensics.get("free_emails", []),
                "has_corp_id": forensics.get("has_corp_id"),
                "has_prepaid": forensics.get("has_prepaid"),
                "has_cod": forensics.get("has_cod"),
                "restrictive_refund_clauses": forensics.get("restrictive_refund_clauses", []),
                "forensic_flags": flags,
                "text_excerpt": forensics.get("text_excerpt", ""),
            }
            ai_audit = self._audit_with_groq(url or f"https://{host}/", host, evidence)
            if ai_audit:
                live_data["ai_audit"] = ai_audit
                self._live_cache[cache_key] = (now, live_data)

        if ai_audit:
            result["ai_audit"] = ai_audit
            ai_risk = float(ai_audit.get("scam_risk", 0.0))
            verdict = ai_audit.get("verdict", "")
            if verdict == "SCAM_OR_UNAUTHORIZED" and ai_risk >= 0.70:
                score = max(score, 0.55 * score + 0.45 * ai_risk, 0.72)
                if ai_audit.get("reason"):
                    flags.insert(0, f"AI Merchant Audit: {ai_audit['reason']}")
            elif verdict == "LEGITIMATE" and ai_risk <= 0.25 and imp_score < 0.80:
                score = min(score, 0.40)

        result["backend_risk_score"] = round(max(result["backend_risk_score"], min(1.0, score)), 4)
        for fl in flags:
            if fl not in result["indicators"]:
                result["indicators"].append(fl)

        return result

    @staticmethod
    def _fetch_and_forensics(url: str) -> dict:
        try:
            final_url, status, html = fetch_url_html(url, timeout=3.0, max_bytes=350_000)
            if status < 400 and html and len(html) >= 200:
                return analyze_storefront_forensics(final_url or url, html, follow_policy_pages=True, timeout=2.0)
        except Exception:
            pass
        return {
            "is_commerce_or_portal": False,
            "forensic_risk_score": 0.0,
            "forensic_flags": [],
        }

    def search_catalog(self, query: str = "", category: str = "", limit: int = 50) -> list[dict]:
        """Search discovered unauthorized websites catalog CSV."""
        cat_path = os.path.join(self.dataset_dir, "discovered_unauthorized_sites.csv")
        if not os.path.exists(cat_path):
            return []
        df = pd.read_csv(cat_path)
        if query:
            q = query.strip().lower()
            mask = (
                df["domain"].astype(str).str.lower().str.contains(q, na=False)
                | df["reason"].astype(str).str.lower().str.contains(q, na=False)
            )
            df = df[mask]
        if category:
            df = df[df["category"].astype(str).str.lower() == category.strip().lower()]
        return df.head(max(1, min(limit, 500))).fillna("").to_dict(orient="records")

