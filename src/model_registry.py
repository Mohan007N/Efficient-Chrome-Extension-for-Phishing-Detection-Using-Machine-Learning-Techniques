"""
src/model_registry.py — Versioned Model Artifact & Evaluation Metadata Registry

Manages versioned model bundles under `models/registry/<version>/` with:
- Model binaries, feature schemas, encoders, evaluation metrics, dataset lineage,
  and promotion gate verification before updating active inference pointers.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import shutil
import joblib

MODELS_DIR = "models"
REGISTRY_DIR = os.path.join(MODELS_DIR, "registry")
ACTIVE_MANIFEST_PATH = os.path.join(REGISTRY_DIR, "active_manifest.json")

DEFAULT_PROMOTION_GATES = {
    "min_f1": 0.82,
    "min_roc_auc": 0.88,
    "max_fpr": 0.12,
}


def check_promotion_gates(metrics: dict, gates: dict | None = None) -> tuple[bool, list[str]]:
    """Verify whether a candidate model passes minimum validation thresholds before promotion."""
    g = gates or DEFAULT_PROMOTION_GATES
    reasons: list[str] = []
    f1 = float(metrics.get("F1 Score", 0.0) or 0.0)
    auc = float(metrics.get("ROC AUC", 0.0) or 0.0)
    fpr = float(metrics.get("FPR", 1.0) if metrics.get("FPR") is not None else 1.0)

    if f1 < g["min_f1"]:
        reasons.append(f"F1 Score {f1:.4f} < {g['min_f1']}")
    if auc < g["min_roc_auc"]:
        reasons.append(f"ROC AUC {auc:.4f} < {g['min_roc_auc']}")
    if fpr > g["max_fpr"]:
        reasons.append(f"FPR {fpr:.4f} > {g['max_fpr']}")
    return len(reasons) == 0, reasons


def _load_manifest() -> dict:
    if os.path.exists(ACTIVE_MANIFEST_PATH):
        with open(ACTIVE_MANIFEST_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"schema_version": "2.0.0", "models": {}}


def register_model_bundle(
    model_role: str,
    version: str,
    model_obj,
    feature_columns: list[str],
    metrics: dict,
    model_name: str,
    dataset_lineage: dict,
    encoders: dict | None = None,
    active_model_filename: str | None = None,
    active_features_filename: str | None = None,
    active_encoders_filename: str | None = None,
    legacy_alias_filename: str | None = None,
) -> dict:
    """Save versioned model artifacts + metadata and promote only if validation gates pass."""
    os.makedirs(MODELS_DIR, exist_ok=True)
    version_dir = os.path.join(REGISTRY_DIR, f"{model_role}_{version}")
    os.makedirs(version_dir, exist_ok=True)

    passed, gate_reasons = check_promotion_gates(metrics)
    model_path = os.path.join(version_dir, "model.pkl")
    features_path = os.path.join(version_dir, "feature_columns.pkl")
    joblib.dump(model_obj, model_path)
    joblib.dump(feature_columns, features_path)

    enc_path = None
    if encoders is not None:
        enc_path = os.path.join(version_dir, "encoders.pkl")
        joblib.dump(encoders, enc_path)

    metadata = {
        "role": model_role,
        "version": version,
        "algorithm": model_name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "feature_count": len(feature_columns),
        "feature_columns": feature_columns,
        "metrics": metrics,
        "dataset_lineage": dataset_lineage,
        "promotion_passed": passed,
        "promotion_gate_notes": gate_reasons or ["All validation gates passed."],
    }
    with open(os.path.join(version_dir, "metadata.json"), "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    if passed:
        if active_model_filename:
            shutil.copy2(model_path, os.path.join(MODELS_DIR, active_model_filename))
        if legacy_alias_filename:
            shutil.copy2(model_path, os.path.join(MODELS_DIR, legacy_alias_filename))
        if active_features_filename:
            shutil.copy2(features_path, os.path.join(MODELS_DIR, active_features_filename))
        if enc_path and active_encoders_filename:
            shutil.copy2(enc_path, os.path.join(MODELS_DIR, active_encoders_filename))

        manifest = _load_manifest()
        manifest.setdefault("models", {})[model_role] = metadata
        manifest["updated_at"] = datetime.now(timezone.utc).isoformat()
        with open(ACTIVE_MANIFEST_PATH, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

    return metadata


def get_active_registry_manifest() -> dict:
    """Return active model versions, metrics, and training lineage metadata."""
    return _load_manifest()

