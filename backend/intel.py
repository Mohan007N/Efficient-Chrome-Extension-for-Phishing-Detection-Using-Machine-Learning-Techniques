"""
backend/intel.py — Threat Intelligence, Feed Freshness & Domain Metadata Engine (v3.0)

Combines:
1. O(1) lookups against verified threat feeds with explicit timestamps, expiration TTL,
   reliability ratings, and transparent failure reporting (never silently reports loaded when missing/corrupt)
2. Tranco Top-1M popularity context (never equates absence with malice or hosted user content as trusted)
3. SSRF-safe live storefront/HTML inspection (via pinned-IP backend.security.safe_fetch_html)
4. Graceful RDAP domain-age & strict TLS certificate verification checks
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import gzip
import json
import logging
import os
import threading
import time
from urllib.parse import urlparse

import pandas as pd
from dotenv import load_dotenv

from backend.security import PayloadTooLargeError, SSRFBlockedError, safe_fetch_html
from src.features import (
    TRUSTED_DOMAINS,
    detect_brand_impersonation,
    extract_root_domain,
    is_hosted_user_content_subdomain,
    normalize_url,
)
from src.web_forensics import analyze_storefront_forensics, inspect_rdap_domain, inspect_tls_certificate

load_dotenv(override=True)
logger = logging.getLogger("PhishingAPI.Intel")

DEFAULT_FEED_TTL_SECONDS = int(os.getenv("INTEL_FEED_TTL_SECONDS", str(86400 * 7)))
MAX_LIVE_CACHE_ENTRIES = 2000


class UnauthorizedIntelEngine:
    """Thread-safe threat intelligence engine with feed provenance, freshness TTL, and bounded caches."""

    def __init__(
        self,
        dataset_dir: str = "dataset",
        intel_dir: str = "data/intel",
        cache_ttl_seconds: int = 3600,
        feed_ttl_seconds: int = DEFAULT_FEED_TTL_SECONDS,
    ):
        self.dataset_dir = dataset_dir
        self.intel_dir = intel_dir
        self.cache_ttl_seconds = cache_ttl_seconds
        self.feed_ttl_seconds = feed_ttl_seconds

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

        self._domain_meta_cache: dict[str, tuple[float, dict]] = {}
        self._page_forensics_cache: dict[str, tuple[float, dict]] = {}
        self._cache_lock = threading.Lock()
        self._catalog_df: pd.DataFrame | None = None

        self.loaded = False
        self.degraded = False
        self.stale = False
        self.last_loaded_at: float | None = None
        self.feed_updated_at: str | None = None
        self.feed_expires_at: str | None = None
        self.load_errors: list[str] = []
        self.feed_metadata: dict[str, dict] = {}

    def _record_feed_meta(self, name: str, path: str, count: int, reliability: str, ok: bool, error: str | None = None):
        now = time.time()
        mtime = os.path.getmtime(path) if os.path.exists(path) else now
        age_sec = max(0.0, now - mtime)
        expired = age_sec > float(self.feed_ttl_seconds) if os.path.exists(path) else False
        updated_iso = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat() if os.path.exists(path) else None
        expires_iso = (
            datetime.fromtimestamp(mtime + self.feed_ttl_seconds, tz=timezone.utc).isoformat()
            if os.path.exists(path)
            else None
        )
        self.feed_metadata[name] = {
            "loaded": ok,
            "count": int(count),
            "reliability": reliability,
            "updated_at": updated_iso,
            "expires_at": expires_iso,
            "expired": expired,
            "error": error,
        }
        if expired:
            self.stale = True
        if error:
            self.load_errors.append(error)

    def load(self):
        """Load compressed threat intelligence indexes, catalog cache, and feed freshness metadata."""
        self.load_errors = []
        self.feed_metadata = {}
        self.degraded = False
        self.stale = False

        idx_path = os.path.join(self.dataset_dir, "unauthorized_domains.json.gz")
        idx_ok = False
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
                idx_ok = True
                total_domains = (
                    len(self.verified_sites) + len(self.hagezi_fake) + len(self.hagezi_tif)
                    + len(self.phishing_database) + len(self.cert_pl) + len(self.openphish_domains)
                )
                self._record_feed_meta("unauthorized_domains", idx_path, total_domains, "high", True)
                logger.info(
                    f"Loaded threat intelligence in {time.time() - t0:.2f}s: "
                    f"verified={len(self.verified_sites)}, hagezi_fake={len(self.hagezi_fake):,}, "
                    f"hagezi_tif={len(self.hagezi_tif):,}, phish_db={len(self.phishing_database):,}, "
                    f"cert_pl={len(self.cert_pl):,}, openphish={len(self.openphish_domains):,}"
                )
            except Exception as e:
                err = f"Failed loading threat intelligence index {idx_path}: {e}"
                logger.warning(err)
                self._record_feed_meta("unauthorized_domains", idx_path, 0, "high", False, err)
        else:
            err = f"Threat intelligence index missing at {idx_path}."
            logger.warning(err)
            self._record_feed_meta("unauthorized_domains", idx_path, 0, "high", False, err)

        tranco_path = os.path.join(self.dataset_dir, "tranco_top1m.json.gz")
        tranco_ok = False
        if os.path.exists(tranco_path):
            try:
                with gzip.open(tranco_path, "rt", encoding="utf-8") as gz:
                    self.tranco_ranks = json.load(gz)
                tranco_ok = True
                self._record_feed_meta("tranco_top1m", tranco_path, len(self.tranco_ranks), "medium_reputation_only", True)
            except Exception as e:
                err = f"Failed loading Tranco index {tranco_path}: {e}"
                logger.warning(err)
                self._record_feed_meta("tranco_top1m", tranco_path, 0, "medium_reputation_only", False, err)
        else:
            err = f"Tranco index missing at {tranco_path}."
            logger.warning(err)
            self._record_feed_meta("tranco_top1m", tranco_path, 0, "medium_reputation_only", False, err)

        # Pre-cache discovered unauthorized catalog CSV once so /intel/search never hits disk per query
        cat_path = os.path.join(self.dataset_dir, "discovered_unauthorized_sites.csv")
        if os.path.exists(cat_path):
            try:
                self._catalog_df = pd.read_csv(cat_path)
                self._record_feed_meta("discovered_catalog", cat_path, len(self._catalog_df), "verified_catalog", True)
            except Exception as e:
                self.load_errors.append(f"Failed loading catalog {cat_path}: {e}")
                self._catalog_df = None

        self.last_loaded_at = time.time()
        self.loaded = idx_ok and tranco_ok
        self.degraded = not self.loaded or self.stale or bool(self.load_errors)
        meta_idx = self.feed_metadata.get("unauthorized_domains", {})
        self.feed_updated_at = meta_idx.get("updated_at")
        self.feed_expires_at = meta_idx.get("expires_at")

    def status_summary(self) -> dict:
        return {
            "loaded": self.loaded,
            "degraded": self.degraded,
            "stale": self.stale,
            "last_loaded_at": (
                datetime.fromtimestamp(self.last_loaded_at, tz=timezone.utc).isoformat()
                if self.last_loaded_at
                else None
            ),
            "feed_updated_at": self.feed_updated_at,
            "feed_expires_at": self.feed_expires_at,
            "errors": list(self.load_errors),
            "feeds": dict(self.feed_metadata),
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
        """
        Return True ONLY if hostname/registered domain is in TRUSTED_DOMAINS AND NOT a multi-tenant
        hosted user-content subdomain (e.g., sites.google.com, storage.googleapis.com).
        """
        h = (hostname or "").lower().strip().rstrip(".")
        if ":" in h:
            h = h.split(":", 1)[0]
        if not h or is_hosted_user_content_subdomain(h):
            return False
        root = extract_root_domain(h)
        return h in TRUSTED_DOMAINS or root in TRUSTED_DOMAINS

    def get_tranco_rank(self, hostname: str) -> int | None:
        h = (hostname or "").lower().strip().rstrip(".")
        if ":" in h:
            h = h.split(":", 1)[0]
        if not h or is_hosted_user_content_subdomain(h):
            return self.tranco_ranks.get(h)
        root = extract_root_domain(h)
        return self.tranco_ranks.get(h) or self.tranco_ranks.get(root)

    def lookup_registry(self, hostname: str) -> dict:
        """Check hostname and root domain against cached threat intelligence feeds."""
        h = (hostname or "").lower().strip().rstrip(".")
        if ":" in h:
            h = h.split(":", 1)[0]
        root = extract_root_domain(h)

        # Avoid flagging legitimate root provider (e.g. google.com) for user-content subdomains
        candidates = (h,) if is_hosted_user_content_subdomain(h) else (h, root)

        for candidate in candidates:
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
                    "reliability": "high",
                }
            if candidate in self.openphish_domains:
                return {
                    "matched": True,
                    "source": "openphish",
                    "category": "phishing",
                    "reason": f"Domain '{candidate}' is listed in the active OpenPhish feed.",
                    "risk_floor": 0.95,
                    "reliability": "high",
                }
            if candidate in self.cert_pl:
                return {
                    "matched": True,
                    "source": "cert_pl",
                    "category": "phishing",
                    "reason": f"Domain '{candidate}' is flagged in the CERT.pl malicious domain feed.",
                    "risk_floor": 0.94,
                    "reliability": "high",
                }
            if candidate in self.hagezi_fake:
                return {
                    "matched": True,
                    "source": "hagezi_fake",
                    "category": "fake_shop_or_scam",
                    "reason": f"Domain '{candidate}' is flagged in the HaGeZi Fake/Scam storefront feed.",
                    "risk_floor": 0.92,
                    "reliability": "medium",
                }
            if candidate in self.phishing_database:
                return {
                    "matched": True,
                    "source": "phishing_database",
                    "category": "phishing",
                    "reason": f"Domain '{candidate}' appears in the active Phishing.Database feed.",
                    "risk_floor": 0.92,
                    "reliability": "high",
                }
            if candidate in self.hagezi_tif:
                return {
                    "matched": True,
                    "source": "hagezi_tif",
                    "category": "malware_distribution",
                    "reason": f"Domain '{candidate}' appears in the HaGeZi Threat Intelligence Feed.",
                    "risk_floor": 0.91,
                    "reliability": "medium",
                }
            if candidate in self.jarelllama_scams:
                return {
                    "matched": True,
                    "source": "jarelllama_scams",
                    "category": "scam_blocklist",
                    "reason": f"Domain '{candidate}' is listed in the Scam-Blocklist feed.",
                    "risk_floor": 0.88,
                    "reliability": "medium",
                }

        return {"matched": False, "source": None, "category": None, "reason": None, "risk_floor": 0.0, "reliability": None}

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
        and SSRF-safe storefront forensics.
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
        domain_key = host
        target_url = normalize_url(url) if (url and url.startswith(("http://", "https://"))) else f"https://{host}/"
        page_key = target_url

        with self._cache_lock:
            cached_dom = self._domain_meta_cache.get(domain_key)
            cached_page = self._page_forensics_cache.get(page_key)

        dom_valid = cached_dom is not None and (now - cached_dom[0]) < self.cache_ttl_seconds
        page_valid = cached_page is not None and (now - cached_page[0]) < self.cache_ttl_seconds

        if dom_valid and page_valid:
            domain_data = cached_dom[1]
            forensics_info = cached_page[1]
        else:
            with ThreadPoolExecutor(max_workers=3) as pool:
                fut_rdap = None if dom_valid else pool.submit(inspect_rdap_domain, root or host, 2.5)
                fut_tls = None if dom_valid else pool.submit(inspect_tls_certificate, host, 2.5)
                fut_html = None if page_valid else pool.submit(self._safe_fetch_and_forensics, target_url)

                domain_data = (
                    cached_dom[1]
                    if dom_valid
                    else {"rdap": fut_rdap.result(), "tls": fut_tls.result()}
                )
                forensics_info = cached_page[1] if page_valid else fut_html.result()

            with self._cache_lock:
                if not dom_valid:
                    if len(self._domain_meta_cache) >= MAX_LIVE_CACHE_ENTRIES:
                        oldest_k = min(self._domain_meta_cache.items(), key=lambda kv: kv[1][0])[0]
                        del self._domain_meta_cache[oldest_k]
                    self._domain_meta_cache[domain_key] = (now, domain_data)
                if not page_valid:
                    if len(self._page_forensics_cache) >= MAX_LIVE_CACHE_ENTRIES:
                        oldest_pk = min(self._page_forensics_cache.items(), key=lambda kv: kv[1][0])[0]
                        del self._page_forensics_cache[oldest_pk]
                    self._page_forensics_cache[page_key] = (now, forensics_info)

        result["rdap"] = domain_data["rdap"]
        result["tls"] = domain_data["tls"]
        result["forensics"] = forensics_info

        age_days = domain_data["rdap"].get("domain_age_days")
        if age_days is not None and age_days < 90:
            result["indicators"].append(
                f"Recently Registered Domain: Created {age_days} days ago ({domain_data['rdap'].get('created_date')})."
            )

        if domain_data["tls"].get("ssl_error"):
            result["indicators"].append(
                f"TLS Certificate Verification Failure: {domain_data['tls'].get('ssl_error_detail') or 'Invalid or untrusted certificate'}."
            )

        for fl in forensics_info.get("forensic_flags", []):
            if fl not in result["indicators"]:
                result["indicators"].append(fl)

        return result

    @staticmethod
    def _safe_fetch_and_forensics(url: str) -> dict:
        """SSRF-protected page fetch and storefront forensics."""
        try:
            final_url, status, html, redirect_chain = safe_fetch_html(
                url,
                timeout=4.0,
                max_bytes=400_000,
                max_decompressed_bytes=1_000_000,
                max_redirects=3,
            )
            if status < 400 and html and len(html) >= 200:
                forensics = analyze_storefront_forensics(final_url, html, follow_policy_pages=False, timeout=2.0)
                forensics["redirect_chain"] = redirect_chain
                return forensics
        except (SSRFBlockedError, PayloadTooLargeError) as se:
            logger.info(f"Safe fetch blocked or limited for {url}: {se}")
        except Exception:
            pass
        return {
            "is_commerce_or_portal": False,
            "forensic_risk_score": 0.0,
            "forensic_flags": [],
            "redirect_chain": [],
        }

    def search_catalog(self, query: str = "", category: str = "", limit: int = 50) -> list[dict]:
        """Search cached discovered unauthorized websites catalog."""
        if self._catalog_df is None:
            cat_path = os.path.join(self.dataset_dir, "discovered_unauthorized_sites.csv")
            if not os.path.exists(cat_path):
                return []
            self._catalog_df = pd.read_csv(cat_path)

        df = self._catalog_df
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
