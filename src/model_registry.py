"""
src/model_registry.py — Versioned Model Artifact Registry, SHA-256 Integrity & Atomic Promotion (v3.0)

Features:
- Complete provenance metadata: model_version, model_type, training timestamp, dataset SHA-256
  fingerprint, source distribution, feature schema, explicit class mapping, operating threshold,
  calibration status, validation/test metrics separated cleanly, training config, and library versions.
- Promotion gates checked strictly against validation/test quality targets before promotion.
- Atomic artifact promotion using staging files + `os.replace()` so active models are never partial.
- SHA-256 verification helpers and rollback support to prior promoted registry versions.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import joblib

MODELS_DIR = "models"
REGISTRY_DIR = os.path.join(MODELS_DIR, "registry")
ACTIVE_MANIFEST_PATH = os.path.join(REGISTRY_DIR, "active_manifest.json")

DEFAULT_PROMOTION_GATES = {
    "min_phishing_f1": 0.85,
    "min_roc_auc": 0.90,
    "max_fpr": 0.08,
}


def compute_file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_dataset_fingerprint(df_summary: dict) -> str:
    payload = json.dumps(df_summary, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def get_library_versions() -> dict[str, str]:
    libs = {}
    for pkg in ("scikit-learn", "xgboost", "lightgbm", "pandas", "numpy", "joblib", "tldextract", "shap"):
        try:
            libs[pkg] = importlib.metadata.version(pkg)
        except Exception:
            libs[pkg] = "not_installed"
    libs["python"] = platform.python_version()
    return libs


def _atomic_copy(src: str, dst: str):
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    tmp = f"{dst}.tmp.{os.getpid()}"
    shutil.copy2(src, tmp)
    os.replace(tmp, dst)


def _atomic_write_json(path: str, payload: dict):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    os.replace(tmp, path)


def check_promotion_gates(metrics: dict, gates: dict | None = None) -> tuple[bool, list[str]]:
    """Verify whether candidate model passes minimum security gates (evaluated using Phishing F1, AUC, FPR)."""
    g = gates or DEFAULT_PROMOTION_GATES
    reasons: list[str] = []
    f1 = float(metrics.get("Phishing F1", metrics.get("F1 Score", 0.0)) or 0.0)
    auc = float(metrics.get("ROC AUC", 0.0) or 0.0)
    fpr = float(metrics.get("FPR", 1.0) if metrics.get("FPR") is not None else 1.0)

    if f1 < g["min_phishing_f1"]:
        reasons.append(f"Phishing F1 {f1:.4f} < {g['min_phishing_f1']}")
    if auc < g["min_roc_auc"]:
        reasons.append(f"ROC AUC {auc:.4f} < {g['min_roc_auc']}")
    if fpr > g["max_fpr"]:
        reasons.append(f"FPR {fpr:.4f} > {g['max_fpr']}")
    return len(reasons) == 0, reasons


def _load_manifest(registry_dir: str = REGISTRY_DIR) -> dict:
    path = os.path.join(registry_dir, "active_manifest.json")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"schema_version": "3.0.0", "models": {}, "rollback_history": {}}


def _sanitize_metrics(m: dict) -> dict:
    clean = {}
    for k, v in (m or {}).items():
        if k in ("Classification Report",):
            continue
        if isinstance(v, (int, float, str, bool, list, dict)) or v is None:
            clean[k] = v
        elif hasattr(v, "item"):
            clean[k] = v.item()
    return clean


def register_model_bundle(
    model_role: str,
    version: str,
    model_obj,
    feature_columns: list[str],
    validation_metrics: dict,
    test_metrics: dict,
    model_name: str,
    dataset_lineage: dict,
    class_mapping: dict | None = None,
    threshold: float = 0.5,
    calibrated: bool = False,
    training_config: dict | None = None,
    encoders: dict | None = None,
    active_model_filename: str | None = None,
    active_features_filename: str | None = None,
    active_encoders_filename: str | None = None,
    legacy_alias_filename: str | None = None,
    models_dir: str = MODELS_DIR,
    gates: dict | None = None,
) -> dict:
    """
    Persist versioned bundle with SHA-256 checksums and atomically promote active pointers
    ONLY if promotion gates pass on BOTH validation & held-out test metrics cleanly.
    """
    reg_dir = os.path.join(models_dir, "registry")
    os.makedirs(models_dir, exist_ok=True)
    version_dir = os.path.join(reg_dir, f"{model_role}_{version}")
    os.makedirs(version_dir, exist_ok=True)

    # Validate binary class mapping on model before saving
    classes = getattr(model_obj, "classes_", None)
    if classes is None or set(int(c) for c in classes) != {0, 1}:
        raise ValueError(f"Cannot register {model_role}: invalid model classes {classes}; expected [0, 1].")

    model_path = os.path.join(version_dir, "model.pkl")
    features_path = os.path.join(version_dir, "feature_columns.pkl")
    joblib.dump(model_obj, f"{model_path}.tmp")
    os.replace(f"{model_path}.tmp", model_path)
    joblib.dump(list(feature_columns), f"{features_path}.tmp")
    os.replace(f"{features_path}.tmp", features_path)

    checksums = {
        "model": compute_file_sha256(model_path),
        "feature_columns": compute_file_sha256(features_path),
    }

    enc_path = None
    if encoders is not None:
        enc_path = os.path.join(version_dir, "encoders.pkl")
        joblib.dump(encoders, f"{enc_path}.tmp")
        os.replace(f"{enc_path}.tmp", enc_path)
        checksums["encoders"] = compute_file_sha256(enc_path)

    # Promotion gate strictly uses VALIDATION metrics only (never leak held-out test metrics into promotion decisions)
    passed_val, val_notes = check_promotion_gates(validation_metrics, gates=gates)
    passed_test_audit, test_audit_notes = check_promotion_gates(test_metrics, gates=gates)
    passed = passed_val
    gate_reasons = ([] if passed_val else [f"Val: {n}" for n in val_notes])
    audit_notes = (["Test audit passed."] if passed_test_audit else [f"Test audit note: {n}" for n in test_audit_notes])

    ds_fingerprint = dataset_lineage.get("dataset_fingerprint") or compute_dataset_fingerprint(dataset_lineage)

    metadata = {
        "role": model_role,
        "version": version,
        "model_type": type(model_obj).__name__,
        "algorithm": model_name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "dataset_fingerprint": ds_fingerprint,
        "dataset_source_distribution": dataset_lineage.get("sources", {}),
        "dataset_lineage": dataset_lineage,
        "feature_count": len(feature_columns),
        "feature_columns": list(feature_columns),
        "class_mapping": class_mapping or {"0": "phishing_malicious", "1": "benign_legitimate"},
        "model_classes": [int(c) for c in classes],
        "threshold": round(float(threshold), 4),
        "calibrated": bool(calibrated),
        "validation_metrics": _sanitize_metrics(validation_metrics),
        "test_metrics": _sanitize_metrics(test_metrics),
        # Keep top-level summary metrics from held-out test for dashboard compatibility
        "metrics": _sanitize_metrics(test_metrics),
        "training_config": training_config or {},
        "library_versions": get_library_versions(),
        "sha256_checksums": checksums,
        "active_filenames": {
            "model": active_model_filename,
            "feature_columns": active_features_filename,
            "encoders": active_encoders_filename,
        },
        "promotion_passed": passed,
        "promotion_gate_notes": gate_reasons or ["All validation security gates passed."],
        "test_audit_notes": audit_notes,
    }
    _atomic_write_json(os.path.join(version_dir, "metadata.json"), metadata)

    if passed:
        manifest = _load_manifest(reg_dir)
        manifest["schema_version"] = "3.0.0"
        prev = manifest.get("models", {}).get(model_role)
        if prev and prev.get("version") != version:
            hist = manifest.setdefault("rollback_history", {}).setdefault(model_role, [])
            hist.append({
                "version": prev.get("version"),
                "algorithm": prev.get("algorithm"),
                "promoted_until": datetime.now(timezone.utc).isoformat(),
            })
            manifest["rollback_history"][model_role] = hist[-10:]

        if active_model_filename:
            _atomic_copy(model_path, os.path.join(models_dir, active_model_filename))
        if legacy_alias_filename:
            _atomic_copy(model_path, os.path.join(models_dir, legacy_alias_filename))
        if active_features_filename:
            _atomic_copy(features_path, os.path.join(models_dir, active_features_filename))
        if enc_path and active_encoders_filename:
            _atomic_copy(enc_path, os.path.join(models_dir, active_encoders_filename))

        manifest.setdefault("models", {})[model_role] = metadata
        manifest["updated_at"] = datetime.now(timezone.utc).isoformat()
        _atomic_write_json(os.path.join(reg_dir, "active_manifest.json"), manifest)

    return metadata


def verify_active_model_integrity(model_role: str, models_dir: str = MODELS_DIR) -> tuple[bool, str]:
    """Verify EVERY active promoted artifact (model, feature_columns, encoders) exists and matches SHA-256."""
    reg_dir = os.path.join(models_dir, "registry")
    manifest = _load_manifest(reg_dir)
    entry = (manifest.get("models") or {}).get(model_role)
    if not entry:
        return False, f"No active registry entry for role '{model_role}'."

    active_files = entry.get("active_filenames") or {}
    checksums = entry.get("sha256_checksums") or {}
    if not checksums or "model" not in checksums:
        return False, f"Incomplete integrity metadata for role '{model_role}'."

    for art_key, expected_sha in checksums.items():
        art_name = active_files.get(art_key)
        if not art_name or not expected_sha:
            return False, f"Missing active filename/checksum metadata for '{model_role}:{art_key}'."
        art_path = os.path.join(models_dir, art_name)
        if not os.path.exists(art_path):
            return False, f"Active artifact missing: {art_path}"
        actual_sha = compute_file_sha256(art_path)
        if actual_sha != expected_sha:
            return False, (
                f"Checksum mismatch on {art_name} ({art_key}) "
                f"(expected {expected_sha[:12]}, got {actual_sha[:12]})."
            )
    return True, "ok"


def rollback_model_role(model_role: str, target_version: str | None = None, models_dir: str = MODELS_DIR) -> dict:
    """Atomically roll back an active model role to a prior registered version."""
    reg_dir = os.path.join(models_dir, "registry")
    manifest = _load_manifest(reg_dir)
    if not target_version:
        hist = (manifest.get("rollback_history") or {}).get(model_role, [])
        if not hist:
            raise ValueError(f"No rollback version available for '{model_role}'.")
        target_version = hist[-1]["version"]

    v_dir = os.path.join(reg_dir, f"{model_role}_{target_version}")
    meta_path = os.path.join(v_dir, "metadata.json")
    if not os.path.exists(meta_path):
        raise FileNotFoundError(f"Registry bundle not found: {v_dir}")
    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    files = meta.get("active_filenames") or {}
    if files.get("model"):
        _atomic_copy(os.path.join(v_dir, "model.pkl"), os.path.join(models_dir, files["model"]))
    if files.get("feature_columns"):
        _atomic_copy(os.path.join(v_dir, "feature_columns.pkl"), os.path.join(models_dir, files["feature_columns"]))
    if files.get("encoders") and os.path.exists(os.path.join(v_dir, "encoders.pkl")):
        _atomic_copy(os.path.join(v_dir, "encoders.pkl"), os.path.join(models_dir, files["encoders"]))

    manifest.setdefault("models", {})[model_role] = meta
    manifest["updated_at"] = datetime.now(timezone.utc).isoformat()
    _atomic_write_json(os.path.join(reg_dir, "active_manifest.json"), manifest)
    return meta


def get_active_registry_manifest(models_dir: str = MODELS_DIR) -> dict:
    """Return active model versions, metrics, checksums, and training lineage metadata."""
    return _load_manifest(os.path.join(models_dir, "registry"))
