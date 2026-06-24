import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, roc_auc_score
import joblib
import json
import struct
import zlib
import math
import os
import sys
from datetime import datetime, timedelta, timezone, UTC

MODEL_PATH       = "models/isolation_forest.joblib"
BINARY_PATH      = "models/model.isof"
METRICS_PATH     = "models/metrics.json"
REFERENCE_PATH   = "models/reference_scores.npy"
FALLBACK_PATH    = "data/login_events.csv"

CONTAMINATION    = 0.05
N_ESTIMATORS     = 100
RANDOM_STATE     = 42
DAYS_LOOKBACK    = 30
HEADER_SIZE      = 32
NODE_SIZE        = 24
LEAF_SENTINEL    = 0xFFFFFFFF
VERSION          = 1
MAGIC            = b"ISOF"

FEATURE_COLS = [
    "hour_of_day",
    "failed_attempts",
    "device_hash",
    "geo_hash",
    "ip_hash",
    "login_freq",
]

DB_CONFIG = {
    "host"     : "localhost",
    "port"     : 5432,
    "dbname"   : "zerotrust",
    "user"     : "zerotrust_reader",
    "password" : os.environ.get("ZT_DB_PASSWORD", ""),
}


def c(n: int) -> float:
    if n > 2:
        return 2.0 * (math.log(n - 1) + 0.5772156649) - (2.0 * (n - 1) / n)
    elif n == 2:
        return 1.0
    return 0.0


def load_from_database(days: int = DAYS_LOOKBACK) -> pd.DataFrame:
    try:
        import psycopg2
    except ImportError:
        raise RuntimeError("psycopg2 not installed. Run: pip install psycopg2-binary")

    print(f"  Connecting to {DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['dbname']}")
    conn   = psycopg2.connect(**DB_CONFIG)
    cursor = conn.cursor()
    cursor.execute(f"""
        SELECT
            rel.user_id::text                          AS user_id,
            EXTRACT(EPOCH FROM rel.created_at)::bigint AS timestamp_unix,
            rel.feature_vector[1] * 23.0               AS hour_of_day,
            rel.feature_vector[2] * 10.0               AS failed_attempts,
            rel.feature_vector[3] * 1000.0             AS device_hash,
            rel.feature_vector[4] * 1000.0             AS geo_hash,
            rel.feature_vector[5] * 1000.0             AS ip_hash,
            rel.feature_vector[6] * 100.0              AS login_freq,
            CASE WHEN rel.decision = 'BLOCK' THEN 1 ELSE 0 END AS label
        FROM risk_event_log rel
        WHERE rel.created_at >= NOW() - INTERVAL '{days} days'
        AND   rel.feature_vector IS NOT NULL
        ORDER BY rel.created_at ASC;
    """)
    rows    = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    conn.close()

    df = pd.DataFrame(rows, columns=columns)
    print(f"  Rows fetched : {len(df):,}")
    print(f"  Date range   : last {days} days")
    return df


def load_from_csv(path: str = FALLBACK_PATH) -> pd.DataFrame:
    print(f"  Loading from CSV fallback: {path}")
    df = pd.read_csv(path)
    print(f"  Rows loaded  : {len(df):,}")
    return df


def engineer_features(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    d = df.copy()

    already_normalized = (
        "hour_of_day" in d.columns and
        float(d["hour_of_day"].max()) <= 1.0
    )

    if not already_normalized:
        if "hour_of_day" not in d.columns:
            d["hour_of_day"] = pd.to_datetime(
                d["timestamp_unix"], unit="s", utc=True
            ).dt.hour
        d["hour_of_day"]     = d["hour_of_day"] / 23.0
        d["failed_attempts"] = d["failed_attempts"] / 10.0
        d["device_hash"]     = (d["device_hash"] % 1000) / 1000.0
        d["geo_hash"]        = (d["geo_hash"]    % 1000) / 1000.0
        d["ip_hash"]         = (d["ip_hash"]     % 1000) / 1000.0
        d["login_freq"]      = (
            d.groupby("user_id")["timestamp_unix"]
            .transform("count") / 100.0
        )

    X      = d[FEATURE_COLS].values.astype(np.float32)
    labels = d["label"].values if "label" in d.columns else np.zeros(len(d))
    return X, labels


def train(X_normal: np.ndarray) -> IsolationForest:
    model = IsolationForest(
        n_estimators  = N_ESTIMATORS,
        contamination = CONTAMINATION,
        random_state  = RANDOM_STATE,
    )
    model.fit(X_normal)
    return model


def evaluate(model: IsolationForest, X: np.ndarray,
             labels: np.ndarray) -> dict:
    raw_scores = model.decision_function(X)
    preds      = np.where(model.predict(X) == -1, 1, 0)
    auc        = roc_auc_score(labels, -raw_scores) if labels.sum() > 0 else 0.0

    report = classification_report(
        labels, preds,
        target_names=["normal", "attack"],
        output_dict=True,
        zero_division=0,
    )

    normal_scores = raw_scores[labels == 0]
    attack_scores = raw_scores[labels == 1] if labels.sum() > 0 else raw_scores

    threshold_mfa   = float(np.percentile(normal_scores, 5))
    threshold_block = float(np.percentile(attack_scores, 10))
    if threshold_block >= threshold_mfa:
        threshold_block = threshold_mfa - 0.01

    return {
        "roc_auc"             : round(float(auc), 4),
        "false_positive_rate" : round(float(1 - report["normal"]["recall"]), 4),
        "detection_rate"      : round(float(report["attack"]["recall"]), 4),
        "accuracy"            : round(float(report["accuracy"]), 4),
        "precision_attack"    : round(float(report["attack"]["precision"]), 4),
        "recall_attack"       : round(float(report["attack"]["recall"]), 4),
        "f1_attack"           : round(float(report["attack"]["f1-score"]), 4),
        "thresholds"          : {
            "threshold_mfa"   : round(threshold_mfa,   4),
            "threshold_block" : round(threshold_block, 4),
        },
        "training_rows"       : int((labels == 0).sum()),
        "trained_at"          : datetime.now(UTC).isoformat(),
        "n_estimators"        : N_ESTIMATORS,
        "contamination"       : CONTAMINATION,
    }


def register_model_version(
    metrics      : dict,
    file_path    : str,
    training_rows: int,
) -> None:
    try:
        import psycopg2
        conn   = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO ml_model_versions (
                file_path,
                training_date,
                training_data_size,
                false_positive_rate,
                detection_rate,
                active
            ) VALUES (%s, NOW(), %s, %s, %s, TRUE);
        """, (
            file_path,
            training_rows,
            metrics["false_positive_rate"],
            metrics["detection_rate"],
        ))
        conn.commit()
        conn.close()
        print(f"  Model version registered in ml_model_versions")
    except Exception as e:
        print(f"  [WARN] Could not register model version in DB: {e}")
        print(f"  [WARN] Model file is still valid — DB write is non-critical.")


def write_header(n_estimators: int, n_features: int,
                 crc32_value: int) -> bytes:
    header  = bytearray()
    header += MAGIC
    header += struct.pack("<I", VERSION)
    header += struct.pack("<I", n_estimators)
    header += struct.pack("<I", n_features)
    header += struct.pack("<I", HEADER_SIZE)
    header += struct.pack("<I", crc32_value)
    header += b"\x00" * 8
    return bytes(header)


def write_tree(estimator) -> bytes:
    tree = estimator.tree_
    buf  = bytearray()
    for i in range(tree.node_count):
        left      = tree.children_left[i]
        right     = tree.children_right[i]
        feat      = tree.feature[i]
        threshold = tree.threshold[i]
        n_node    = int(tree.n_node_samples[i])
        path_len  = c(n_node)
        left      = LEAF_SENTINEL if left  == -1 else int(left)
        right     = LEAF_SENTINEL if right == -1 else int(right)
        feat      = 0             if feat  == -2 else int(feat)
        buf += struct.pack("<IIIIff",
                           i, left, right, feat, threshold, path_len)
    return bytes(buf)


def serialize(model: IsolationForest, output_path: str) -> str:
    tree_buf = bytearray()
    for estimator in model.estimators_:
        tree_buf += write_tree(estimator)

    crc32_value = zlib.crc32(bytes(tree_buf)) & 0xFFFFFFFF
    header      = write_header(
        len(model.estimators_),
        model.n_features_in_,
        crc32_value,
    )
    final = header + bytes(tree_buf)

    with open(output_path, "wb") as f:
        f.write(final)

    return output_path


def validate(path: str) -> bool:
    with open(path, "rb") as f:
        data = f.read()

    if data[0:4] != MAGIC:
        return False
    stored_crc   = struct.unpack_from("<I", data, 20)[0]
    computed_crc = zlib.crc32(data[HEADER_SIZE:]) & 0xFFFFFFFF
    return stored_crc == computed_crc


def main(use_db: bool = True) -> None:
    print("=" * 60)
    print("ZeroTrustEngine — Retraining Pipeline")
    print("=" * 60)

    print(f"\n[1/5] Loading behavioral data...")
    if use_db:
        try:
            df = load_from_database(days=DAYS_LOOKBACK)
        except Exception as e:
            print(f"  [WARN] DB connection failed: {e}")
            print(f"  [WARN] Falling back to CSV.")
            df = load_from_csv()
    else:
        df = load_from_csv()

    print(f"\n[2/5] Engineering features...")
    X, labels = engineer_features(df)
    X_normal  = X[labels == 0]
    print(f"  Total rows   : {len(X):,}")
    print(f"  Normal rows  : {len(X_normal):,}")
    print(f"  Attack rows  : {int(labels.sum()):,}")

    if len(X_normal) < 100:
        print("\n  [ERROR] Not enough normal samples to retrain (minimum 100).")
        sys.exit(1)

    print(f"\n[3/5] Training Isolation Forest...")
    model = train(X_normal)
    joblib.dump(model, MODEL_PATH)
    print(f"  Model saved  → {MODEL_PATH}")

    print(f"\n[4/5] Evaluating and serializing...")
    metrics = evaluate(model, X, labels)

    binary_path = serialize(model, BINARY_PATH)
    print(f"  Binary saved → {binary_path}")

    if not validate(binary_path):
        print("  [ERROR] Binary validation failed. Aborting.")
        sys.exit(1)
    print(f"  Validation   : PASSED")

    raw_scores = model.decision_function(X)
    np.save(REFERENCE_PATH, raw_scores)
    print(f"  Reference    → {REFERENCE_PATH}")

    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"  Metrics      → {METRICS_PATH}")

    register_model_version(metrics, os.path.abspath(BINARY_PATH), metrics["training_rows"])

    print(f"\n[5/5] Summary")
    print(f"  ROC-AUC          : {metrics['roc_auc']}")
    print(f"  Detection Rate   : {metrics['detection_rate']}")
    print(f"  False Positive   : {metrics['false_positive_rate']}")
    print(f"  Trained at       : {metrics['trained_at']}")
    print(f"  Training rows    : {metrics['training_rows']:,}")

    print("\n✓ Retraining complete.\n")


if __name__ == "__main__":
    use_db = "--csv" not in sys.argv
    main(use_db=use_db)