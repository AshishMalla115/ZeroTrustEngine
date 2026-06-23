import numpy as np
import pandas as pd
import joblib
import json
import os
from scipy import stats

MODEL_PATH      = "models/isolation_forest.joblib"
REFERENCE_PATH  = "models/reference_scores.npy"
METRICS_PATH    = "models/metrics.json"
FULL_PATH       = "data/login_events.csv"

DRIFT_THRESHOLD = 0.01
FEATURE_COLS    = [
    "hour_of_day",
    "failed_attempts",
    "device_hash",
    "geo_hash",
    "ip_hash",
    "login_freq",
]


def load_features(csv_path: str) -> np.ndarray:
    df = pd.read_csv(csv_path)

    df["hour_of_day"]     = df["hour_of_day"] / 23.0
    df["failed_attempts"] = df["failed_attempts"] / 10.0
    df["device_hash"]     = (df["device_hash"] % 1000) / 1000.0
    df["geo_hash"]        = (df["geo_hash"]    % 1000) / 1000.0
    df["ip_hash"]         = (df["ip_hash"]     % 1000) / 1000.0
    df["login_freq"]      = (
        df.groupby("user_id")["timestamp_unix"]
        .transform("count") / 100.0
    )

    return df[FEATURE_COLS].values.astype(np.float32)


def save_reference_scores(scores: np.ndarray) -> None:
    np.save(REFERENCE_PATH, scores)
    print(f"  Reference scores saved → {REFERENCE_PATH}")
    print(f"  Samples : {len(scores):,}")
    print(f"  Mean    : {scores.mean():.4f}")
    print(f"  Std     : {scores.std():.4f}")
    print(f"  Min     : {scores.min():.4f}")
    print(f"  Max     : {scores.max():.4f}")


def compute_reference() -> np.ndarray:
    print("=" * 60)
    print("ZeroTrustEngine — Drift Detector: Computing Reference")
    print("=" * 60)

    model = joblib.load(MODEL_PATH)
    X     = load_features(FULL_PATH)

    scores = model.decision_function(X)

    print()
    save_reference_scores(scores)
    print("\n✓ Reference scores saved.\n")
    return scores


def detect_drift(live_scores: np.ndarray) -> dict:
    print("=" * 60)
    print("ZeroTrustEngine — Drift Detector: Running KS Test")
    print("=" * 60)

    if not os.path.exists(REFERENCE_PATH):
        print("\n  [ERROR] Reference scores not found.")
        print("  Run: python drift_detector.py --compute-reference\n")
        return {"drift_detected": False, "error": "no_reference"}

    reference_scores = np.load(REFERENCE_PATH)

    ks_stat, p_value = stats.ks_2samp(reference_scores, live_scores)

    drift_detected = p_value < DRIFT_THRESHOLD

    mean_shift = float(live_scores.mean() - reference_scores.mean())
    std_shift  = float(live_scores.std()  - reference_scores.std())

    if abs(mean_shift) < 0.02:
        severity = "none"
    elif abs(mean_shift) < 0.05:
        severity = "low"
    elif abs(mean_shift) < 0.10:
        severity = "medium"
    else:
        severity = "high"

    result = {
        "drift_detected"    : drift_detected,
        "ks_statistic"      : round(float(ks_stat), 6),
        "p_value"           : round(float(p_value), 6),
        "drift_threshold"   : DRIFT_THRESHOLD,
        "severity"          : severity if drift_detected else "none",
        "mean_shift"        : round(mean_shift, 4),
        "std_shift"         : round(std_shift,  4),
        "reference_samples" : len(reference_scores),
        "live_samples"      : len(live_scores),
    }

    print(f"\n  Reference samples : {len(reference_scores):,}")
    print(f"  Live samples      : {len(live_scores):,}")
    print(f"\n  KS Statistic      : {ks_stat:.6f}")
    print(f"  P-value           : {p_value:.6f}")
    print(f"  Drift threshold   : {DRIFT_THRESHOLD}")
    print(f"\n  Mean shift        : {mean_shift:+.4f}")
    print(f"  Std shift         : {std_shift:+.4f}")
    print(f"  Severity          : {result['severity'].upper()}")
    print()

    if drift_detected:
        print(f"  [DRIFT DETECTED] p={p_value:.6f} < {DRIFT_THRESHOLD}")
        print(f"  Severity: {severity.upper()}")
        print(f"  Action  : Retraining recommended.")
    else:
        print(f"  [NO DRIFT] p={p_value:.6f} >= {DRIFT_THRESHOLD}")
        print(f"  Model distribution is stable.")

    print()
    return result


def run_on_current_data() -> dict:
    model  = joblib.load(MODEL_PATH)
    X      = load_features(FULL_PATH)
    scores = model.decision_function(X)
    return detect_drift(scores)


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--compute-reference":
        compute_reference()
    else:
        run_on_current_data()