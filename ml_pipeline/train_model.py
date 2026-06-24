import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    precision_recall_curve,
)
import joblib
import json
import os

MODEL_PATH    = "models/isolation_forest.joblib"
METRICS_PATH  = "models/metrics.json"
DATA_PATH     = "data/normal_samples.csv"
FULL_PATH     = "data/login_events.csv"

CONTAMINATION = 0.05
N_ESTIMATORS  = 100
RANDOM_STATE  = 42

FEATURE_COLS  = [
    "hour_of_day",
    "failed_attempts",
    "device_hash",
    "geo_hash",
    "ip_hash",
    "login_freq",
]


def load_features(csv_path: str) -> tuple[np.ndarray, pd.DataFrame]:
    df = pd.read_csv(csv_path)

    df["hour_of_day"]    = df["hour_of_day"] / 23.0
    df["failed_attempts"] = df["failed_attempts"] / 10.0
    df["device_hash"]    = (df["device_hash"] % 1000) / 1000.0
    df["geo_hash"]       = (df["geo_hash"]    % 1000) / 1000.0
    df["ip_hash"]        = (df["ip_hash"]     % 1000) / 1000.0
    df["login_freq"]     = (
        df.groupby("user_id")["timestamp_unix"]
        .transform("count") / 100.0
    )

    X = df[FEATURE_COLS].values.astype(np.float32)
    return X, df


def train(X_normal: np.ndarray) -> IsolationForest:
    model = IsolationForest(
        n_estimators  = N_ESTIMATORS,
        contamination = CONTAMINATION,
        random_state  = RANDOM_STATE,
    )
    model.fit(X_normal)
    return model


def tune_thresholds(
    scores: np.ndarray,
    labels: np.ndarray,
) -> dict:
    normal_scores = scores[labels == 0]
    attack_scores = scores[labels == 1]

    threshold_mfa   = float(np.percentile(normal_scores, 5))
    threshold_block = float(np.percentile(attack_scores, 10))

    if threshold_block >= threshold_mfa:
        threshold_block = threshold_mfa - 0.01

    return {
        "threshold_allow" : round(float(np.max(scores)),    4),
        "threshold_mfa"   : round(threshold_mfa,            4),
        "threshold_block" : round(threshold_block,          4),
    }


def evaluate(
    model   : IsolationForest,
    full_path: str,
) -> dict:
    X_full, df = load_features(full_path)
    labels     = df["label"].values

    raw_scores   = model.decision_function(X_full)
    predictions  = model.predict(X_full)
    preds_binary = np.where(predictions == -1, 1, 0)

    report = classification_report(
        labels,
        preds_binary,
        target_names=["normal", "attack"],
        output_dict=True,
    )

    cm  = confusion_matrix(labels, preds_binary)
    auc = roc_auc_score(labels, -raw_scores)

    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0

    thresholds = tune_thresholds(raw_scores, labels)

    metrics = {
        "n_estimators"    : N_ESTIMATORS,
        "contamination"   : CONTAMINATION,
        "roc_auc"         : round(auc,  4),
        "false_positive_rate" : round(fpr, 4),
        "detection_rate"  : round(tpr,  4),
        "accuracy"        : round(report["accuracy"], 4),
        "precision_attack": round(report["attack"]["precision"], 4),
        "recall_attack"   : round(report["attack"]["recall"],    4),
        "f1_attack"       : round(report["attack"]["f1-score"],  4),
        "thresholds"      : thresholds,
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        },
    }

    print("\n  Classification Report")
    print("  " + "-" * 48)
    print(classification_report(
        labels,
        preds_binary,
        target_names=["normal", "attack"],
    ))

    print("  Confusion Matrix")
    print(f"    True Negatives  (normal  → normal) : {tn:>5}")
    print(f"    False Positives (normal  → attack) : {fp:>5}")
    print(f"    False Negatives (attack  → normal) : {fn:>5}")
    print(f"    True Positives  (attack  → attack) : {tp:>5}")
    print(f"\n  ROC-AUC           : {auc:.4f}")
    print(f"  False Positive Rate: {fpr:.4f}  ({fpr*100:.1f}% of normal users flagged)")
    print(f"  Detection Rate     : {tpr:.4f}  ({tpr*100:.1f}% of attacks caught)")
    print(f"\n  Thresholds (blended score = rule*0.6 + ml*0.4)")
    print(f"    MFA trigger : score >= {thresholds['threshold_mfa']}")
    print(f"    Block trigger: score >= {thresholds['threshold_block']}")

    return metrics


def main() -> None:
    print("=" * 60)
    print("ZeroTrustEngine — Stage 3: Isolation Forest Training")
    print("=" * 60)

    os.makedirs("models", exist_ok=True)

    print("\n[1/3] Loading normal samples...")
    X_normal, _ = load_features(DATA_PATH)
    print(f"      Shape : {X_normal.shape}")
    print(f"      Features: {FEATURE_COLS}")

    print("\n[2/3] Training Isolation Forest...")
    print(f"      n_estimators  = {N_ESTIMATORS}")
    print(f"      contamination = {CONTAMINATION}")
    model = train(X_normal)
    joblib.dump(model, MODEL_PATH)
    print(f"      Model saved → {MODEL_PATH}")

    print("\n[3/3] Evaluating on full dataset...")
    metrics = evaluate(model, FULL_PATH)

    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"\n  Metrics saved → {METRICS_PATH}")

    print("\n✓ Stage 3 complete.")


if __name__ == "__main__":
    main()