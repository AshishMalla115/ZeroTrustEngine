# ZeroTrustEngine — Model Format Specification
**File:** `model.isof`  
**Version:** 1  
**Authors:** Adnaan (Layer 2), Uthkarsh (Layer 1)  
**Status:** Final — do not modify without both authors agreeing

---

## Overview

`model.isof` is a custom binary file produced by the Python training
pipeline (Layer 2) and consumed by the C inference engine (Layer 1).
It encodes a trained Isolation Forest as a flat array of nodes preceded
by a 32-byte header.

The file has two sections:
[ Header — 32 bytes ]
[ Tree data — N × 24 bytes per node ]

No footer. No checksum at end of file. CRC32 lives in the header only.

---

## Header Layout

Total size: **32 bytes**

| Offset | Size | Type    | Field        | Value / Notes                          |
|--------|------|---------|--------------|----------------------------------------|
| 0      | 4    | char[4] | magic        | ASCII `ISOF` — file identity check     |
| 4      | 4    | uint32  | version      | `1` — single uint32, little-endian     |
| 8      | 4    | uint32  | n_estimators | Number of trees (currently 100)        |
| 12     | 4    | uint32  | n_features   | Number of input features (always 6)    |
| 16     | 4    | uint32  | data_offset  | Byte offset where tree data begins (32)|
| 20     | 4    | uint32  | crc32        | CRC32 of all bytes after byte 32       |
| 24     | 8    | uint8[8]| reserved     | Zero-filled, reserved for future use   |

All multi-byte integers are **little-endian**.

### CRC32 Computation
crc32_value = zlib.crc32(file_bytes[32:]) & 0xFFFFFFFF

Computed over tree data only (everything after the header).
Stored at offset 20. Verified by C loader before reading any nodes.

---

## Node Structure

Each node is **24 bytes**, little-endian.

| Offset | Size | Type    | Field        | Notes                                      |
|--------|------|---------|--------------|--------------------------------------------|
| 0      | 4    | uint32  | node_id      | Zero-based index within this tree          |
| 4      | 4    | uint32  | left_child   | Index of left child. `0xFFFFFFFF` if leaf  |
| 8      | 4    | uint32  | right_child  | Index of right child. `0xFFFFFFFF` if leaf |
| 12     | 4    | uint32  | feature      | Feature index to split on. 0 if leaf       |
| 16     | 4    | float32 | threshold    | Split threshold value                      |
| 20     | 4    | float32 | path_length  | Expected path length c(n) at this node     |

### Leaf Sentinel
left_child  == 0xFFFFFFFF  AND
right_child == 0xFFFFFFFF

Both fields must equal `0xFFFFFFFF` to identify a leaf node.
Using `0` as sentinel is invalid — node index 0 is the root node.

---

## Tree Layout in File

Trees are written sequentially with no separator between them.
The C loader identifies tree boundaries by scanning for `node_id == 0`.

[ Tree 0 node 0 ][ Tree 0 node 1 ] ... [ Tree 0 node N ]
[ Tree 1 node 0 ][ Tree 1 node 1 ] ... [ Tree 1 node N ]
...
[ Tree 99 node 0 ] ... [ Tree 99 node N ]

Node indexes within each tree are **relative to that tree's start**.
The C loader stores `tree_offsets[t]` and computes:

```c
node_idx = tree_offsets[t] + node->left_child;
```

---

## Feature Vector

The model expects exactly **6 float32 features** in this order:

| Index | Column           | Source field (C struct)        | Normalization              |
|-------|------------------|-------------------------------|----------------------------|
| 0     | hour_of_day      | `timestamp_unix` → tm_hour    | `hour / 23.0`              |
| 1     | failed_attempts  | `event->failed_attempts`      | `failed_attempts / 10.0`   |
| 2     | device_hash      | `event->device_hash`          | `(hash % 1000) / 1000.0`   |
| 3     | geo_hash         | `event->geo_hash`             | `(hash % 1000) / 1000.0`   |
| 4     | ip_hash          | `event->ip_hash`              | `(hash % 1000) / 1000.0`   |
| 5     | login_freq       | `profile->login_count`        | `login_count / 100.0`      |

All values are **float32**. Order is fixed — changing order breaks inference.

---

## Anomaly Score Formula

avg_path  = sum of path_length at leaf across all trees / n_trees
c(256)    = 2 * (ln(255) + 0.5772156649) - (2 * 255 / 256)

= 11.0506...   (constant — precompute once)
anomaly_score = pow(2.0, -avg_path / c(256))

- `n = 256` — sklearn default `max_samples` per tree
- Score range: 0.0 to 1.0
- Higher score = more anomalous

---

## Blended Scoring Formula

The C engine blends rule-based and ML scores:

final_score = (rule_score * 0.6) + (ml_score * 0.4)
final_score = clamp(final_score, 0.0, 1.0)

Decision thresholds applied to `final_score`:

| Range                                      | Decision     |
|--------------------------------------------|--------------|
| `final_score < score_threshold_mfa`        | ALLOW        |
| `score_threshold_mfa <= score < threshold_block` | MFA_REQUIRED |
| `final_score >= score_threshold_block`     | BLOCK        |

Risk levels:

| Range              | Level    |
|--------------------|----------|
| score < 0.3        | LOW      |
| 0.3 <= score < 0.6 | MEDIUM   |
| 0.6 <= score < 0.8 | HIGH     |
| score >= 0.8       | CRITICAL |

---

## File Stats (current build)

| Property        | Value         |
|-----------------|---------------|
| File size       | 381,920 bytes |
| Header          | 32 bytes      |
| Tree data       | 381,888 bytes |
| Trees           | 100           |
| Features        | 6             |
| Total nodes     | 15,912        |
| Leaf nodes      | 8,006         |
| CRC32           | 0xde3ac3b2    |
| sklearn version | 1.8.0         |

---

## Validation

Run before every delivery:

python validate_model.py

All 12 checks must pass. Do not deliver `model.isof` if any check fails.