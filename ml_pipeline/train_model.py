import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report
import joblib
import os

MODEL_PATH   = "models/isolation_forest.joblib"
DATA_PATH    = "data/normal_samples.csv"
FULL_PATH    = "data/login_events.csv"
CONTAMINATION = 0.05
N_ESTIMATORS  = 100

def load_features(csv_path: str) -> np.ndarray:
    df = pd.read_csv(csv_path)
    df["hour_of_day"] = df["hour_of_day"] / 23.0
    df["failed_attempts"] = df["failed_attempts"] / 10.0
    df["device_hash"] = (df["device_hash"] % 1000) / 1000.0
    df["geo_hash"] = (df["geo_hash"] % 1000) / 1000.0
    df["ip_hash"] = (df["ip_hash"] % 1000) / 1000.0
    df["login_freq"] = df.groupby("user_id")["timestamp_unix"].transform("count") / 100.0
    features = ["hour_of_day", "failed_attempts", "device_hash",
                "geo_hash", "ip_hash", "login_freq"]
    return df[features].values.astype(np.float32)

def train(X_normal: np.ndarray) -> IsolationForest:
    model = IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination=CONTAMINATION,
        random_state=42
    )
    model.fit(X_normal)
    return model

def evaluate(model: IsolationForest, full_path: str):
    df = pd.read_csv(full_path)
    X_full = load_features(full_path)
    preds = model.predict(X_full)
    preds_binary = np.where(preds == -1, 1, 0)
    print("\n=== Model Evaluation ===")
    print(classification_report(df["label"], preds_binary,
          target_names=["normal", "attack"]))
    
def main():
    os.makedirs("models", exist_ok=True)
    print("[1/3] Loading normal samples...")
    X_normal = load_features(DATA_PATH)
    print(f"      Shape: {X_normal.shape}")
    print("[2/3] Training Isolation Forest...")
    model = train(X_normal)
    joblib.dump(model, MODEL_PATH)
    print(f"      Model saved → {MODEL_PATH}")
    print("[3/3] Evaluating on full dataset...")
    evaluate(model, FULL_PATH)
    print("\n✓ Stage 3 complete.")

if __name__ == "__main__":
    main()