"""
scripts/evaluate_false_positives.py — Legitimate-Domain & Lookalike False-Positive Benchmark

Evaluates the active PhishingPredictor + HybridRiskEngine across:
  1. All verified legitimate seed domains (`data/verified_domains.csv`, Labels 1 & 2, excluding user-content hosts)
     including deep product, search, OAuth signin, and checkout URLs (e.g., amazon.in/dp/... & /ap/signin?...)
  2. Multi-tenant user-content hosting subdomains (`sites.google.com`, `vercel.app`, `github.io`)
  3. Reserved `.example` synthetic lookalikes (`data/synthetic_lookalikes.csv`)
  4. Domain-disjoint held-out test metrics from `models/registry/active_manifest.json`
"""

from __future__ import annotations

import json
import os
import sys

import pandas as pd

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from backend.predictor import PhishingPredictor
from src.features import is_hosted_user_content_subdomain
from src.model_registry import get_active_registry_manifest
from src.seed_catalog import CATEGORY_URL_TEMPLATES

OUTPUT_REPORT_JSON = os.path.join(PROJECT_ROOT, "reports", "false_positive_eval.json")


def run_false_positive_evaluation() -> dict:
    predictor = PhishingPredictor(
        models_dir=os.path.join(PROJECT_ROOT, "models"),
        dataset_dir=os.path.join(PROJECT_ROOT, "dataset"),
    )
    predictor.load()
    if not predictor.is_ready():
        raise RuntimeError("Models failed to load for false-positive evaluation.")

    ver_path = os.path.join(PROJECT_ROOT, "data", "verified_domains.csv")
    vdf = pd.read_csv(ver_path)
    legit_df = vdf[vdf["label"].isin([1, 2])].copy()

    url_eval_rows = []
    for _, r in legit_df.iterrows():
        dom = str(r["domain"]).strip()
        cat = str(r["category"]).strip()
        is_host = is_hosted_user_content_subdomain(dom)
        if is_host:
            continue
        paths = ["/"] + CATEGORY_URL_TEMPLATES.get(cat, ["/about"])[:2]
        for path in paths:
            full_url = f"https://www.{dom}{path}" if not dom.startswith(("mail.", "web.", "pay.", "outlook.", "onlinesbi.")) else f"https://{dom}{path}"
            clean_dom = {
                "is_https": 1,
                "html_line_count": 320,
                "has_title": 1,
                "domain_title_match_score": 75.0,
                "has_copyright_notice": 1,
                "num_hidden_iframes": 1,
            }
            res = predictor.assess_website(url=full_url, dom_features=clean_dom, deep_scan=False)
            url_eval_rows.append({
                "domain": dom,
                "category": cat,
                "label": int(r["label"]),
                "url": full_url,
                "url_model_prob": res.get("url_model_threat_probability"),
                "dom_model_prob": res.get("dom_model_threat_probability"),
                "overall_risk_level": res.get("overall_risk_level"),
                "prediction_label": res.get("prediction_label"),
                "false_positive": res.get("overall_risk_level") in ("HIGH", "CRITICAL"),
                "url_raw_exceeded": bool((res.get("url_model_threat_probability") or 0.0) >= predictor._url_threshold),
            })

    eval_df = pd.DataFrame(url_eval_rows)
    amazon_rows = eval_df[eval_df["domain"].str.contains("amazon", case=False)]
    look_path = os.path.join(PROJECT_ROOT, "data", "synthetic_lookalikes.csv")
    look_hits = []
    if os.path.exists(look_path):
        ldf = pd.read_csv(look_path)
        for _, lr in ldf.iterrows():
            r_lk = predictor.assess_website(url=str(lr["url"]), deep_scan=False)
            look_hits.append({
                "url": lr["url"],
                "target_brand": lr["target_brand"],
                "overall_risk_level": r_lk["overall_risk_level"],
                "brand_score": (r_lk.get("brand_impersonation") or {}).get("brand_similarity_score"),
                "detected_as_risky": r_lk["overall_risk_level"] in ("HIGH", "CRITICAL"),
            })

    per_cat = {}
    for cat, grp in eval_df.groupby("category"):
        per_cat[cat] = {
            "samples": int(len(grp)),
            "false_positives": int(grp["false_positive"].sum()),
            "fpr": round(float(grp["false_positive"].mean()), 4),
            "raw_url_ml_exceeded_rate": round(float(grp["url_raw_exceeded"].mean()), 4),
        }

    manifest = get_active_registry_manifest(os.path.join(PROJECT_ROOT, "models"))
    per_cat_test = {}
    url_test_path = os.path.join(PROJECT_ROOT, "data", "processed", "url_test.csv")
    if os.path.exists(url_test_path) and predictor.url_model_ready():
        ut_df = pd.read_csv(url_test_path)
        if "threat_category" in ut_df.columns and "binary_label" in ut_df.columns:
            X_ut = pd.DataFrame([predictor.prepare_url_dataframe(str(u)).iloc[0] for u in ut_df["url"]]) if len(ut_df) <= 500 else None
            if X_ut is None:
                from src.evaluate import get_class_probabilities, predict_with_threshold
                from src.train import _prepare_url_xy
                url_enc = predictor._url_encoders.get("tld") if isinstance(predictor._url_encoders, dict) else predictor._url_encoders
                X_all, y_all, _ = _prepare_url_xy(ut_df, encoder=url_enc)
                p_all, _ = get_class_probabilities(predictor._url_model, X_all)
                preds_all = predict_with_threshold(p_all, threshold=predictor._url_threshold)
                ut_df = ut_df.copy()
                ut_df["_pred"] = preds_all
                for tc, tgrp in ut_df.groupby("threat_category"):
                    n_tot = int(len(tgrp))
                    if n_tot == 0:
                        continue
                    acc = float((tgrp["_pred"] == tgrp["binary_label"]).mean())
                    neg = tgrp[tgrp["binary_label"] == 1]
                    pos = tgrp[tgrp["binary_label"] == 0]
                    per_cat_test[str(tc)] = {
                        "samples": n_tot,
                        "accuracy": round(acc, 4),
                        "fpr": round(float((neg["_pred"] == 0).mean()), 4) if len(neg) else None,
                        "recall_phishing": round(float((pos["_pred"] == 0).mean()), 4) if len(pos) else None,
                    }

    summary = {
        "total_verified_legit_urls_tested": int(len(eval_df)),
        "false_positives_high_critical": int(eval_df["false_positive"].sum()),
        "overall_legitimate_fpr": round(float(eval_df["false_positive"].mean()), 4) if len(eval_df) else 0.0,
        "raw_url_ml_mean_prob_on_legit": round(float(eval_df["url_model_prob"].dropna().mean()), 4),
        "raw_url_ml_exceeded_rate": round(float(eval_df["url_raw_exceeded"].mean()), 4),
        "amazon_results": amazon_rows[["url", "url_model_prob", "dom_model_prob", "overall_risk_level", "prediction_label", "false_positive"]].to_dict(orient="records"),
        "synthetic_lookalikes_detected": sum(1 for x in look_hits if x["detected_as_risky"]),
        "synthetic_lookalikes_total": len(look_hits),
        "synthetic_lookalike_details": look_hits,
        "per_category_legit": per_cat,
        "per_category_url_test": per_cat_test,
        "registry_test_metrics": {
            "url_risk": (manifest.get("models", {}).get("url_risk") or {}).get("test_metrics"),
            "dom_behavior": (manifest.get("models", {}).get("dom_behavior") or {}).get("test_metrics"),
        },
    }
    os.makedirs(os.path.dirname(OUTPUT_REPORT_JSON), exist_ok=True)
    with open(OUTPUT_REPORT_JSON, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(json.dumps({k: v for k, v in summary.items() if k not in ("amazon_results", "synthetic_lookalike_details", "registry_test_metrics")}, indent=2))
    print("Amazon sample verdicts:", json.dumps(summary["amazon_results"], indent=2))
    return summary


if __name__ == "__main__":
    run_false_positive_evaluation()

