import struct
import zlib
import math
import numpy as np
import joblib
import os

# ── constants ────────────────────────────────────────────────
MAGIC        = b"ISOF"
VERSION      = 1          # single uint32
HEADER_SIZE  = 32         # bytes — data starts right after
MODEL_PATH   = "models/isolation_forest.joblib"
OUTPUT_PATH  = "models/model.isof"


# ── helper: expected path length c(n) ────────────────────────
def c(n: int) -> float:
    """
    Expected path length for Isolation Forest scoring.
    This is the correction factor used in the anomaly score formula.
    n = number of samples that reached this node.
    """
    if n > 2:
        return 2.0 * (math.log(n - 1) + 0.5772156649) - (2.0 * (n - 1) / n)
    elif n == 2:
        return 1.0
    else:
        return 0.0


# ── write header (32 bytes) ───────────────────────────────────
def write_header(n_estimators: int, n_features: int, 
                 crc32_value: int) -> bytes:
    """
    Builds the 32-byte header.
    Offset  0- 3 : magic ISOF
    Offset  4- 7 : version uint32 = 1
    Offset  8-11 : n_estimators uint32
    Offset 12-15 : n_features uint32
    Offset 16-19 : data_offset uint32 = 32
    Offset 20-23 : crc32 of all bytes after header
    Offset 24-31 : reserved zeros
    """
    header = bytearray()
    header += MAGIC                                      # 4 bytes
    header += struct.pack("<I", VERSION)                 # 4 bytes
    header += struct.pack("<I", n_estimators)            # 4 bytes
    header += struct.pack("<I", n_features)              # 4 bytes
    header += struct.pack("<I", HEADER_SIZE)             # 4 bytes  data_offset = 32
    header += struct.pack("<I", crc32_value)             # 4 bytes  crc32
    header += b"\x00" * 8                               # 8 bytes  reserved
    return bytes(header)                                 # total = 32 bytes


# ── write one tree ────────────────────────────────────────────
def write_tree(estimator, n_samples: int) -> bytes:
    """
    Writes all nodes of one tree.
    Each node is 24 bytes:
      node_id   uint32  4 bytes
      left      uint32  4 bytes  (0 if leaf)
      right     uint32  4 bytes  (0 if leaf)
      feature   uint32  4 bytes  (0 if leaf)
      threshold float32 4 bytes
      path_len  float32 4 bytes  ← c(n) expected path length
    """
    tree   = estimator.tree_
    buf    = bytearray()

    for i in range(tree.node_count):
        left      = tree.children_left[i]
        right     = tree.children_right[i]
        feat      = tree.feature[i]
        threshold = tree.threshold[i]

        # number of samples that reached this node
        n_node = int(tree.n_node_samples[i])

        # expected path length for this node
        path_length = c(n_node)

        # clean up sklearn sentinel values
        left      = 0 if left  == -1 else int(left)
        right     = 0 if right == -1 else int(right)
        feat      = 0 if feat  == -2 else int(feat)

        buf += struct.pack("<IIIIff",
                           i,           # node_id
                           left,        # left child
                           right,       # right child
                           feat,        # split feature
                           threshold,   # split threshold
                           path_length) # c(n) — NOT tree.max_depth
    return bytes(buf)


# ── main serializer ───────────────────────────────────────────
def serialize():
    os.makedirs("models", exist_ok=True)

    print("[1/4] Loading trained model...")
    model        = joblib.load(MODEL_PATH)
    estimators   = model.estimators_
    n_estimators = len(estimators)
    n_features   = model.n_features_in_
    n_samples    = model.max_samples_

    print(f"      Trees: {n_estimators}, Features: {n_features}")

    # ── step 1: write all tree data first ──
    print("[2/4] Writing tree data...")
    tree_buf = bytearray()
    for estimator in estimators:
        tree_buf += write_tree(estimator, n_samples)

    # ── step 2: compute CRC32 of tree data only ──
    print("[3/4] Computing CRC32...")
    crc32_value = zlib.crc32(bytes(tree_buf)) & 0xFFFFFFFF

    # ── step 3: write header with CRC32 baked in ──
    print("[4/4] Writing header and saving file...")
    header = write_header(n_estimators, n_features, crc32_value)

    # ── step 4: combine header + tree data ──
    final_buf = header + bytes(tree_buf)

    with open(OUTPUT_PATH, "wb") as f:
        f.write(final_buf)

    print(f"\n  File written  : {OUTPUT_PATH}")
    print(f"  File size     : {len(final_buf):,} bytes")
    print(f"  Trees written : {n_estimators}")
    print(f"  CRC32         : {crc32_value:#010x}")
    print(f"  Header size   : {len(header)} bytes")
    print(f"  Data offset   : {HEADER_SIZE}")
    print("\n✓ Serializer updated — all 5 changes applied.")


if __name__ == "__main__":
    serialize()