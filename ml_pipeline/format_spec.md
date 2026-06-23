# model.isof — Binary Format Specification

## Header (32 bytes total)
| Offset | Size | Type     | Field           | Value/Notes                  |
|--------|------|----------|-----------------|------------------------------|
| 0      | 4    | char[4]  | magic           | "ISOF" (identifies our file) |
| 4      | 2    | uint16_t | version_major   | 1                            |
| 6      | 2    | uint16_t | version_minor   | 0                            |
| 8      | 4    | uint32_t | n_estimators    | number of trees in model     |
| 12     | 4    | uint32_t | n_features      | 6 (our feature vector size)  |
| 16     | 4    | uint32_t | max_depth       | max depth of any tree        |
| 20     | 4    | uint32_t | file_size_bytes | total file size in bytes     |
| 24     | 8    | uint8_t[8]| reserved       | zero-padded, for future use  |

## Feature Vector Definition (6 features, fixed order)
| Index | Name            | Source Field        | Type    | Normalization        |
|-------|-----------------|---------------------|---------|----------------------|
| 0     | hour_of_day     | timestamp_unix      | float32 | divide by 23.0       |
| 1     | failed_attempts | failed_attempts     | float32 | divide by 10.0       |
| 2     | device_hash     | device_hash         | float32 | modulo 1000 / 1000.0 |
| 3     | geo_hash        | geo_hash            | float32 | modulo 1000 / 1000.0 |
| 4     | ip_hash         | ip_hash             | float32 | modulo 1000 / 1000.0 |
| 5     | login_freq      | user_id + timestamp | float32 | divide by 100.0      |

All 6 values are written as float32 (4 bytes each = 24 bytes per feature vector).
## Tree Data

Each tree is stored sequentially after the header.
For each tree, the following node structure repeats for every node:

| Offset | Size | Type     | Field         | Notes                          |
|--------|------|----------|---------------|--------------------------------|
| 0      | 4    | uint32_t | node_id       | unique ID of this node         |
| 4      | 4    | uint32_t | left_child    | node_id of left child          |
| 8      | 4    | uint32_t | right_child   | node_id of right child         |
| 12     | 4    | uint32_t | feature_index | which of the 6 features to split on |
| 16     | 4    | float32  | threshold     | split value at this node       |
| 20     | 4    | float32  | node_depth    | depth of this node in the tree |

A leaf node is identified by: left_child == 0 AND right_child == 0
Each node is 24 bytes.
Total tree size = n_nodes * 24 bytes.

## Checksum (last 4 bytes of file)

| Offset      | Size | Type     | Field    | Notes                              |
|-------------|------|----------|----------|------------------------------------|
| end - 4     | 4    | uint32_t | checksum | CRC32 of all bytes before this field |

Python writes: checksum = zlib.crc32(all_bytes_before_checksum)
C reads back : verifies crc32(file_bytes[:-4]) == last_4_bytes
If mismatch → reject file, log error, do not load model.
## Agreed By

| Role         | Name     | Date       | Signature |
|--------------|----------|------------|-----------|
| ML Pipeline  | Adnaan   | YYYY-MM-DD | _________ |
| C Engine     | Uthkarsh | YYYY-MM-DD | _________ |

This document is frozen once both parties sign.
No changes to byte offsets, field order, or types after sign-off.
Any change requires a version_major bump in the header.