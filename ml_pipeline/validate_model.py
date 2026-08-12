import struct
import zlib
import sys
import os

MODEL_PATH    = "models/model.isof"
MAGIC         = b"ISOF"
VERSION       = 1
HEADER_SIZE   = 32
NODE_SIZE     = 24
LEAF_SENTINEL = 0xFFFFFFFF
N_TREES       = 100
N_FEATURES    = 6
DATA_OFFSET   = 32


def validate(path: str = MODEL_PATH) -> bool:
    results = []

    if not os.path.exists(path):
        print(f"[FAIL] File not found: {path}")
        return False

    with open(path, "rb") as f:
        data = f.read()

    file_size = len(data)

    def check(label: str, passed: bool, detail: str = ""):
        status = "PASS" if passed else "FAIL"
        line   = f"  [{status}] {label}"
        if detail:
            line += f" — {detail}"
        print(line)
        results.append(passed)

    print(f"\nValidating: {path}")
    print(f"File size : {file_size:,} bytes")
    print("-" * 52)

    check(
        "File size minimum",
        file_size > HEADER_SIZE,
        f"{file_size} bytes"
    )

    if file_size < HEADER_SIZE:
        print("\n[FAIL] File too small to read header. Aborting.")
        return False

    magic = data[0:4]
    check(
        "Magic bytes",
        magic == MAGIC,
        f"got {magic}"
    )

    version = struct.unpack_from("<I", data, 4)[0]
    check(
        "Version",
        version == VERSION,
        f"expected {VERSION}, got {version}"
    )

    n_trees = struct.unpack_from("<I", data, 8)[0]
    check(
        "Tree count",
        n_trees == N_TREES,
        f"expected {N_TREES}, got {n_trees}"
    )

    n_features = struct.unpack_from("<I", data, 12)[0]
    check(
        "Feature count",
        n_features == N_FEATURES,
        f"expected {N_FEATURES}, got {n_features}"
    )

    data_offset = struct.unpack_from("<I", data, 16)[0]
    check(
        "Data offset",
        data_offset == DATA_OFFSET,
        f"expected {DATA_OFFSET}, got {data_offset}"
    )

    stored_crc = struct.unpack_from("<I", data, 20)[0]
    computed_crc = zlib.crc32(data[HEADER_SIZE:]) & 0xFFFFFFFF
    check(
        "CRC32 checksum",
        stored_crc == computed_crc,
        f"stored {stored_crc:#010x}, computed {computed_crc:#010x}"
    )

    reserved = data[24:32]
    check(
        "Reserved bytes",
        reserved == b"\x00" * 8,
        f"got {reserved.hex()}"
    )

    tree_data_size = file_size - HEADER_SIZE
    check(
        "Tree data alignment",
        tree_data_size % NODE_SIZE == 0,
        f"{tree_data_size} bytes / {NODE_SIZE} = {tree_data_size / NODE_SIZE:.1f} nodes"
    )

    total_nodes = tree_data_size // NODE_SIZE
    check(
        "Total node count",
        total_nodes > 0,
        f"{total_nodes} nodes across {n_trees} trees"
    )

    leaf_count   = 0
    broken_nodes = 0
    offset       = HEADER_SIZE

    for i in range(total_nodes):
        left  = struct.unpack_from("<I", data, offset + 4)[0]
        right = struct.unpack_from("<I", data, offset + 8)[0]

        is_leaf          = (left == LEAF_SENTINEL and right == LEAF_SENTINEL)
        has_zero_sentinel = (left == 0 and right == 0 and i != 0)

        if is_leaf:
            leaf_count += 1
        if has_zero_sentinel:
            broken_nodes += 1

        offset += NODE_SIZE

    check(
        "Leaf sentinel correctness",
        broken_nodes == 0,
        f"{broken_nodes} nodes with invalid zero sentinel found"
    )

    check(
        "Leaf node count",
        leaf_count > 0,
        f"{leaf_count} leaf nodes detected"
    )

    print("-" * 52)
    passed = sum(results)
    total  = len(results)

    if all(results):
        print(f"\n  VALIDATION PASSED ({passed}/{total} checks)\n")
    else:
        print(f"\n  VALIDATION FAILED ({passed}/{total} checks passed)\n")

    return all(results)


if __name__ == "__main__":
    path   = sys.argv[1] if len(sys.argv) > 1 else MODEL_PATH
    result = validate(path)
    sys.exit(0 if result else 1)