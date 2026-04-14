import struct
import zlib
import numpy as np
import joblib
import os

MAGIC          = b"ISOF"
VERSION_MAJOR  = 1
VERSION_MINOR  = 0
MODEL_PATH     = "models/isolation_forest.joblib"
OUTPUT_PATH    = "models/model.isof"

def write_header(buf: bytearray, n_estimators: int, 
                 n_features: int, max_depth: int):
    buf += MAGIC
    buf += struct.pack("<HH", VERSION_MAJOR, VERSION_MINOR)
    buf += struct.pack("<IIII", n_estimators, n_features, 
                       max_depth, 0)
    buf += b"\x00" * 8
    return buf
def write_tree(buf: bytearray, estimator) -> bytearray:
    tree = estimator.tree_
    n_nodes = tree.node_count
    for i in range(n_nodes):
        left  = tree.children_left[i]
        right = tree.children_right[i]
        feat  = tree.feature[i]
        thresh = tree.threshold[i]
        depth = float(tree.max_depth)
        left  = 0 if left  == -1 else left
        right = 0 if right == -1 else right
        feat  = 0 if feat  == -2 else feat
        buf += struct.pack("<IIIIff", i, left, right, 
                           feat, thresh, depth)
    return buf
def write_checksum(buf: bytearray) -> bytearray:
    checksum = zlib.crc32(bytes(buf)) & 0xFFFFFFFF
    buf += struct.pack("<I", checksum)
    return buf
def serialize():
    os.makedirs("models", exist_ok=True)
    print("[1/4] Loading trained model...")
    model = joblib.load(MODEL_PATH)
    estimators = model.estimators_
    n_estimators = len(estimators)
    n_features   = model.n_features_in_
    max_depth    = max(e.tree_.max_depth for e in estimators)
    print(f"      Trees: {n_estimators}, Features: {n_features}, Max depth: {max_depth}")

    buf = bytearray()

    print("[2/4] Writing header...")
    buf = write_header(buf, n_estimators, n_features, max_depth)

    print("[3/4] Writing tree data...")
    for i, estimator in enumerate(estimators):
        buf = write_tree(buf, estimator)

    print("[4/4] Writing checksum...")
    buf = write_checksum(buf)

    # Fix file_size_bytes in header at offset 20
    file_size = len(buf)
    struct.pack_into("<I", buf, 20, file_size)

    with open(OUTPUT_PATH, "wb") as f:
        f.write(buf)

    print(f"\n  File written : {OUTPUT_PATH}")
    print(f"  File size    : {file_size:,} bytes")
    print(f"  Trees written: {n_estimators}")
    print(f"  Checksum     : {zlib.crc32(bytes(buf[:-4])) & 0xFFFFFFFF:#010x}")
    print("\n✓ Stage 4 complete.")

if __name__ == "__main__":
    serialize()