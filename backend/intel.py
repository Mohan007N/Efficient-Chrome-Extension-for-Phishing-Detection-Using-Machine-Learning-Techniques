"""
backend/intel.py — Threat Intelligence & Domain Metadata Engine (Model 5)

Combines:
1. O(1) lookups against verified threat feeds (OpenPhish, HaGeZi Fake/TIF, CERT.pl,
   Phishing.Database, Scam-Blocklist, optional PhishTank/URLhaus)
2. Tranco Top-1M popularity context (never equates absence with malice or presence alone as safe)
3. SSRF-safe live storefront/HTML inspection (via backend.security.safe_fetch_html)
4. Graceful RDAP domain-age & TLS certificate metadata checks (missing RDAP/DNS never treated as proof of malice)
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import gzip
import json
import logging
import os
import time
from urllib.parse import urlparse

import pandas as pd
from dotenv import load_dotenv

from backend.security import SSRFBlockedError, safe_fetch_html
from src.features import TRUSTED_DOMAINS, detect_brand_impersonation, extract_root_domain
from src.web_forensics import analyze_storefront_forensics, inspect_rdap_domain, inspect_tls_certificate

load_dotenv(override=True)
logger = logging.getLogger("PhishingAPI.Intel")


class UnauthorizedIntelEngine:
    """Thread-safe threat intelligence, domain metadata, and storefront forensics engine."""

    def __init__(self, dataset_dir: str = "dataset", cache_ttl_seconds: int = 3600):
        self.dataset_dir = dataset_dir
        self.cache_ttl_seconds = cache_ttl_seconds

        self.verified_sites: dict[str, dict] = {
            "vlebazaar.in": {
                "url": "https://vlebazaar.in/",
                "category": "payment_risk",
                "source": "verified_consumer_fraud_registry",
                "reason": "High-volume non-delivery & prepaid order complaints; missing corporate email/GSTIN and store-credit refund clause.",
            }
        }
        self.hagezi_fake: set[str] = set()
        self.hagezi_tif: set[str] = set()
        self.phishing_database: set[str] = set()
        self.cert_pl: set[str] = set()
        self.openphish_domains: set[str] = set()
        self.jarelllama_scams: set[str] = set()
        self.tranco_ranks: dict[str, int] = {}

        self._live_cache: dict[str, tuple[float, dict]] = {}
        self.loaded = False
        self.last_loaded_at: float | None = None

    def load(self):
        """Load compressed domain intelligence indexes and Tranco rankings into memory."""
        idx_path = os.path.join(self.dataset_dir, "unauthorized_domains.json.gz")
        if os.path.exists(idx_path):
            try:
                t0 = time.time()
                with gzip.open(idx_path, "rt", encoding="utf-8") as gz:
                    data = json.load(gz)
                self.verified_sites.update(data.get("verified", {}))
                self.hagezi_fake = set(data.get("hagezi_fake", []))
                self.hagezi_tif = set(data.get("hagezi_tif", []))
                self.phishing_database = set(data.get("phishing_database", []))
                self.cert_pl = set(data.get("cert_pl", []))
                self.openphish_domains = set(data.get("openphish_domains", []))
                self.jarelllama_scams = set(data.get("jarelllama_scams", []))
                logger.info(
                    f"Loaded threat intelligence in {time.time() - t0:.2f}s: "
                    f"verified={len(self.verified_sites)}, hagezi_fake={len(self.hagezi_fake):,}, "
                    f"hagezi_tif={len(self.hagezi_tif):,}, phish_db={len(self.phishing_database):,}, "
                    f"cert_pl={len(self.cert_pl):,}, openphish={len(self.openphish_domains):,}"
                )
            except Exception as e:
                logger.warning(f"Failed loading {idx_path}: {e}")
        else:
            logger.warning(f"Threat intelligence index not found at {idx_path}. Operating with built-in baseline.")

        tranco_path = os.path.join(self.dataset_dir, "tranco_top1m.json.gz")
        if os.path.exists(tranco_path):
            try:
                with gzip.open(tranco_path, "rt", encoding="utf-8") as gz:
                    self.tranco_ranks = json.load(gz)
            except Exception as e:
                logger.warning(f"Failed loading {tranco_path}: {e}")

        self.loaded = True
        self.last_loaded_at = time.time()

    def status_summary(self) -> dict:
        return {
            "loaded": self.loaded,
            "verified_count": len(self.verified_sites),
            "hagezi_fake_count": len(self.hagezi_fake),
            "hagezi_tif_count": len(self.hagezi_tif),
            "phishing_database_count": len(self.phishing_database),
            "cert_pl_count": len(self.cert_pl),
            "openphish_count": len(self.openphish_domains),
            "scam_blocklist_count": len(self.jarelllama_scams),
            "tranco_count": len(self.tranco_ranks),
        }

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
        """Check hostname and root domain against cached threat intelligence feeds."""
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
                    "category": meta.get("category", "payment_risk"),
                    "reason": meta.get("reason", "Confirmed fraud/scam entry."),
                    "risk_floor": 0.94,
                }
            if candidate in self.openphish_domains:
                return {
                    "matched": True,
                    "source": "openphish",
                    "category": "phishing",
                    "reason": f"Domain '{candidate}' is listed in the active OpenPhish feed.",
                    "risk_floor": 0.95,
                }
            if candidate in self.cert_pl:
                return {
                    "matched": True,
                    "source": "cert_pl",
                    "category": "phishing",
                    "reason": f"Domain '{candidate}' is flagged in the CERT.pl malicious domain feed.",
                    "risk_floor": 0.94,
                }
            if candidate in self.hagezi_fake:
                return {
                    "matched": True,
                    "source": "hagezi_fake",
                    "category": "fake_shop_or_scam",
                    "reason": f"Domain '{candidate}' is flagged in the HaGeZi Fake/Scam storefront feed.",
                    "risk_floor": 0.92,
                }
            if candidate in self.phishing_database:
                return {
                    "matched": True,
                    "source": "phishing_database",
                    "category": "phishing",
                    "reason": f"Domain '{candidate}' appears in the active Phishing.Database feed.",
                    "risk_floor": 0.92,
                }
            if candidate in self.hagezi_tif:
                return {
                    "matched": True,
                    "source": "hagezi_tif",
                    "category": "malware_distribution",
                    "reason": f"Domain '{candidate}' appears in the HaGeZi Threat Intelligence Feed.",
                    "risk_floor": 0.91,
                }
            if candidate in self.jarelllama_scams:
                return {
                    "matched": True,
                    "source": "jarelllama_scams",
                    "category": "scam_blocklist",
                    "reason": f"Domain '{candidate}' is listed in the Scam-Blocklist feed.",
                    "risk_floor": 0.88,
                }

        return {"matched": False, "source": None, "category": None, "reason": None, "risk_floor": 0.0}

    def inspect_domain(
        self,
        url: str,
        hostname: str,
        features_dict: dict | None = None,
        deep_scan: bool = True,
        use_ai_audit: bool = False,
    ) -> dict:
        """
        Gather threat intelligence, Tranco rank, brand similarity, RDAP age, TLS info,
        and SSRF-safe storefront forensics. Missing RDAP/DNS is disclosed gracefully and
        never assumed to prove malicious intent.
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
            "indicators": [],
        }

        if reg["matched"] and reg["reason"]:
            result["indicators"].append(f"Threat Intelligence ({reg['source']}): {reg['reason']}")

        if imp_score >= 0.80 and matched_brand:
            result["indicators"].append(
                f"Brand Impersonation: Domain '{root}' resembles protected brand '{matched_brand}'."
            )

        if not deep_scan or not host or "." not in host:
            return result

        now = time.time()
        cache_key = root or host
        cached = self._live_cache.get(cache_key)
        if cached and (now - cached[0]) < self.cache_ttl_seconds:
            live_data = cached[1]
        else:
            target_url = url if (url and url.startswith(("http://", "https://"))) else f"https://{host}/"
            with ThreadPoolExecutor(max_workers=3) as pool:
                fut_rdap = pool.submit(inspect_rdap_domain, host, 2.5)
                fut_tls = pool.submit(inspect_tls_certificate, host, 2.5)
                fut_html = pool.submit(self._safe_fetch_and_forensics, target_url)
                rdap_info = fut_rdap.result()
                tls_info = fut_tls.result()
                forensics_info = fut_html.result()

            live_data = {"rdap": rdap_info, "tls": tls_info, "forensics": forensics_info}
            self._live_cache[cache_key] = (now, live_data)

        result["rdap"] = live_data["rdap"]
        result["tls"] = live_data["tls"]
        result["forensics"] = live_data["forensics"]

        age_days = live_data["rdap"].get("domain_age_days")
        if age_days is not None and age_days < 90:
            result["indicators"].append(
                f"Recently Registered Domain: Created {age_days} days ago ({live_data['rdap'].get('created_date')})."
            )

        for fl in live_data["forensics"].get("forensic_flags", []):
            if fl not in result["indicators"]:
                result["indicators"].append(fl)

        return result

    @staticmethod
    def _safe_fetch_and_forensics(url: str) -> dict:
        """SSRF-protected page fetch and storefront forensics (gracefully returns empty on block/timeout)."""
        try:
            final_url, status, html, redirect_chain = safe_fetch_html(url, timeout=4.0, max_bytes=400_000, max_redirects=3)
            if status < 400 and html and len(html) >= 200:
                forensics = analyze_storefront_forensics(final_url, html, follow_policy_pages=False, timeout=2.0)
                forensics["redirect_chain"] = redirect_chain
                return forensics
        except SSRFBlockedError as se:
            logger.info(f"SSRF or DNS validation blocked fetch for {url}: {se}")
        except Exception:
            pass
        return {
            "is_commerce_or_portal": False,
            "forensic_risk_score": 0.0,
            "forensic_flags": [],
            "redirect_chain": [],
        }

    def search_catalog(self, query: str = "", category: str = "", limit: int = 50) -> list[dict]:
        """Search discovered unauthorized websites catalog CSV if present."""
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
