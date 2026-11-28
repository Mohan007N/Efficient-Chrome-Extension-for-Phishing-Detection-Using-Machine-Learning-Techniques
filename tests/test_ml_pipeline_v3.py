import os
import shutil
import sys
import tempfile

import numpy as np
import pandas as pd
import pytest
from sklearn.linear_model import LogisticRegression

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.dataset_validation import (
    detect_conflicting_labels,
    domain_grouped_train_val_test_split,
)
from src.evaluate import (
    CLASS_BENIGN,
    CLASS_PHISHING,
    calculate_metrics,
    get_class_probabilities,
    optimize_phishing_threshold,
    predict_with_threshold,
    resolve_class_indices,
)
from src.model_registry import (
    get_active_registry_manifest,
    register_model_bundle,
    rollback_model_role,
    verify_active_model_integrity,
)


def test_resolve_class_indices_and_reversed_order_invariance():
    rng = np.random.default_rng(42)
    X = rng.normal(size=(40, 3))
    X[:20, 0] -= 2.5
    X[20:, 0] += 2.5
    y = np.array([CLASS_PHISHING] * 20 + [CLASS_BENIGN] * 20)

    clf = LogisticRegression().fit(X, y)
    p_idx, b_idx = resolve_class_indices(clf)
    assert clf.classes_[p_idx] == CLASS_PHISHING
    assert clf.classes_[b_idx] == CLASS_BENIGN

    prob_phish, prob_benign = get_class_probabilities(clf, X)
    assert np.allclose(prob_phish + prob_benign, 1.0)
    assert prob_phish[:20].mean() > 0.70

    class ReversedWrapper:
        def __init__(self, inner):
            self.inner = inner
            self.classes_ = np.array([1, 0])

        def predict_proba(self, X_in):
            p = self.inner.predict_proba(X_in)
            return p[:, ::-1]

    rev = ReversedWrapper(clf)
    rev_phish, rev_benign = get_class_probabilities(rev, X)
    assert np.allclose(rev_phish, prob_phish)
    assert np.allclose(rev_benign, prob_benign)

    class BrokenSingleClass:
        classes_ = np.array([1])

    with pytest.raises(ValueError):
        resolve_class_indices(BrokenSingleClass())


def test_validation_threshold_tuning_and_phishing_metrics():
    rng = np.random.default_rng(7)
    y_val = np.array([0] * 50 + [1] * 50)
    p_phish = np.concatenate([
        rng.uniform(0.55, 0.99, size=50),
        rng.uniform(0.01, 0.45, size=50),
    ])
    chosen_thr, thr_stats = optimize_phishing_threshold(y_val, p_phish, max_fpr=0.10)
    assert 0.2 <= chosen_thr <= 0.85
    assert thr_stats["threshold"] == chosen_thr

    preds = predict_with_threshold(p_phish, threshold=chosen_thr)
    eval_out = calculate_metrics(y_val, preds, p_phish)
    assert eval_out["Phishing F1"] >= 0.85
    assert eval_out["Benign F1"] >= 0.85
    assert eval_out["PR AUC"] >= 0.90
    assert eval_out["Positive Class"].startswith("0")
    assert eval_out["Confusion Matrix"]["tp_phishing"] >= 40


def test_domain_grouped_split_and_conflict_quarantine():
    rows = []
    for i in range(40):
        root = f"site{i // 2}.invalid"
        rows.append({
            "url": f"https://{root}/p{i}",
            "root_domain": root,
            "binary_label": i % 2,
            "confidence": 1.0,
            "operational_status": "Benign" if i % 2 == 1 else "Malicious",
        })
    rows.append({
        "url": "https://site0.invalid/p0",
        "root_domain": "site0.invalid",
        "binary_label": 1,
        "confidence": 1.0,
        "operational_status": "Benign",
    })
    df_raw = pd.DataFrame(rows)
    clean_df, stats = detect_conflicting_labels(df_raw)
    assert stats["conflicting_url_count"] >= 1
    row_conflict = clean_df[clean_df["url"] == "https://site0.invalid/p0"]
    assert len(row_conflict) == 1
    assert int(row_conflict["binary_label"].iloc[0]) == 0

    train, val, test = domain_grouped_train_val_test_split(clean_df, group_col="root_domain")
    assert set(train["root_domain"]).isdisjoint(set(val["root_domain"]))
    assert set(train["root_domain"]).isdisjoint(set(test["root_domain"]))
    assert set(val["root_domain"]).isdisjoint(set(test["root_domain"]))


def test_model_registry_integrity_tampering_and_rollback():
    tmp_dir = tempfile.mkdtemp(prefix="ws_reg_test_")
    try:
        X = np.array([[0.0], [0.1], [1.0], [1.1]])
        y = np.array([0, 0, 1, 1])
        m1 = LogisticRegression().fit(X, y)
        m2 = LogisticRegression().fit(X, y)

        good_metrics = {"Phishing F1": 0.92, "ROC AUC": 0.96, "FPR": 0.03}
        register_model_bundle(
            model_role="url_risk",
            version="v3.0.1",
            model_obj=m1,
            feature_columns=["f0"],
            validation_metrics=good_metrics,
            test_metrics=good_metrics,
            model_name="LogReg",
            dataset_lineage={"total_rows": 4, "sources": {"synthetic": 4}},
            threshold=0.52,
            calibrated=True,
            active_model_filename="url_model.pkl",
            active_features_filename="url_feature_columns.pkl",
            models_dir=tmp_dir,
        )
        ok, msg = verify_active_model_integrity("url_risk", models_dir=tmp_dir)
        assert ok, msg

        register_model_bundle(
            model_role="url_risk",
            version="v3.0.2",
            model_obj=m2,
            feature_columns=["f0"],
            validation_metrics={"Phishing F1": 0.94, "ROC AUC": 0.97, "FPR": 0.02},
            test_metrics={"Phishing F1": 0.93, "ROC AUC": 0.96, "FPR": 0.02},
            model_name="LogReg",
            dataset_lineage={"total_rows": 4, "sources": {"synthetic": 4}},
            threshold=0.50,
            calibrated=True,
            active_model_filename="url_model.pkl",
            active_features_filename="url_feature_columns.pkl",
            models_dir=tmp_dir,
        )
        manifest = get_active_registry_manifest(tmp_dir)
        assert manifest["models"]["url_risk"]["version"] == "v3.0.2"

        # Tamper with active artifact and confirm SHA-256 verification fails
        active_file = os.path.join(tmp_dir, "url_model.pkl")
        with open(active_file, "ab") as f:
            f.write(b"TAMPER")
        ok_bad, _ = verify_active_model_integrity("url_risk", models_dir=tmp_dir)
        assert not ok_bad

        rollback_model_role("url_risk", target_version="v3.0.1", models_dir=tmp_dir)
        assert get_active_registry_manifest(tmp_dir)["models"]["url_risk"]["version"] == "v3.0.1"
        ok_rb, msg_rb = verify_active_model_integrity("url_risk", models_dir=tmp_dir)
        assert ok_rb, msg_rb
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
